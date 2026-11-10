//! Hostile bytes must not make a decoder panic or reserve unbounded memory.
//!
//! The proof decoder reads up to 64 KiB that the presenter controls. The key
//! decoder reads a file the verifier owns, and the command-line tool checks
//! its digest first; the key cases here cover a verifier that pinned a bad
//! file. This file holds one test, so no other test thread allocates while
//! it measures.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicUsize, Ordering},
};
use zkar_prover::{proofs::CompressionVerifierKey, relation::UniformCircuit, sealed};

/// No input below may make the proof decoder hold more than this at one time.
/// The largest peak measured when the test was written was 1,114,263 bytes.
const PROOF_PEAK_LIMIT: usize = 4 * 1024 * 1024;
/// The same kind of limit for the key decoder. The largest peak measured was
/// 2,105,349 bytes.
const KEY_PEAK_LIMIT: usize = 8 * 1024 * 1024;

struct CountingAllocator;

static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
static PEAK_BYTES: AtomicUsize = AtomicUsize::new(0);

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn record_allocation(size: usize) {
    let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed).saturating_add(size);
    let mut peak = PEAK_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_BYTES.compare_exchange_weak(peak, live, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => peak = observed,
        }
    }
}

fn record_deallocation(size: usize) {
    let mut live = LIVE_BYTES.load(Ordering::Relaxed);
    loop {
        let next = live.saturating_sub(size);
        match LIVE_BYTES.compare_exchange_weak(live, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => live = observed,
        }
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_deallocation(layout.size());
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            if new_size >= layout.size() {
                record_allocation(new_size - layout.size());
            } else {
                record_deallocation(layout.size() - new_size);
            }
        }
        new_pointer
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DecodeStatus {
    Accepted,
    Rejected,
    Panicked,
}

fn measure<T, E>(decode: impl FnOnce() -> Result<T, E>) -> (DecodeStatus, usize) {
    let baseline = LIVE_BYTES.load(Ordering::Relaxed);
    PEAK_BYTES.store(baseline, Ordering::Relaxed);
    let status = match catch_unwind(AssertUnwindSafe(decode)) {
        Ok(Ok(value)) => {
            drop(value);
            DecodeStatus::Accepted
        }
        Ok(Err(error)) => {
            drop(error);
            DecodeStatus::Rejected
        }
        Err(_) => DecodeStatus::Panicked,
    };
    let peak = PEAK_BYTES.load(Ordering::Relaxed).saturating_sub(baseline);
    (status, peak)
}


fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

/// `length` bytes, zero or seeded noise, with `prefix` written as a
/// little-endian length every `step` bytes.
fn prefix_stream(prefix: u64, length: usize, step: usize, noise: bool) -> Vec<u8> {
    let mut state = 0x1234_5678_9abc_def1_u64;
    let mut bytes: Vec<u8> = (0..length)
        .map(|_| if noise { xorshift(&mut state) as u8 } else { 0 })
        .collect();
    let mut offset = 0;
    while offset + 8 <= length {
        bytes[offset..offset + 8].copy_from_slice(&prefix.to_le_bytes());
        offset += step;
    }
    bytes
}

/// A stream of eight-byte words. Most are small, so the decoder goes deep
/// into the structure before it meets a large length.
fn mixed_length_stream(state: &mut u64, length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    let mut offset = 0;
    while offset + 8 <= length {
        let word = match xorshift(state) % 10 {
            0..=4 => xorshift(state) % 4,
            5..=6 => xorshift(state) % 64,
            7 => 43_690,
            8 => 1 << 20,
            _ => xorshift(state),
        };
        bytes[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
        offset += 8;
    }
    bytes
}

fn hostile_streams() -> Vec<(String, Vec<u8>)> {
    let mut streams = Vec::new();
    for length in [0_usize, 1, 7, 8, 31, 64, 511, 4096, sealed::MAX_PROOF_BYTES] {
        let mut state = 0x4d59_5df4_d0f3_3173 ^ length as u64;
        let noise = (0..length).map(|_| xorshift(&mut state) as u8).collect();
        streams.push((format!("noise, {length} bytes"), noise));
    }
    for length in [31_usize, 4096, sealed::MAX_PROOF_BYTES] {
        for step in [8_usize, 16, 24, 32, 40, 64, 72, 104] {
            for prefix in [
                1_u64,
                3,
                255,
                4096,
                43_690,
                65_536,
                1 << 20,
                1 << 24,
                1 << 32,
                1 << 40,
                u64::MAX,
            ] {
                for noise in [false, true] {
                    streams.push((
                        format!("prefix {prefix} every {step} of {length} bytes, noise {noise}"),
                        prefix_stream(prefix, length, step, noise),
                    ));
                }
            }
        }
    }
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for round in 0..1000 {
        let length = [31_usize, 511, 4096, sealed::MAX_PROOF_BYTES][round % 4];
        streams.push((
            format!("mixed lengths, round {round}, {length} bytes"),
            mixed_length_stream(&mut state, length),
        ));
    }
    streams
}

fn shortest_valid_proof() -> String {
    for length in 0..8192 {
        let encoded = URL_SAFE_NO_PAD.encode(vec![0; length]);
        if sealed::decode_proof(&encoded).is_ok() {
            return encoded;
        }
    }
    panic!("no short canonical proof encoding was found");
}

fn decode_key(bytes: &[u8]) -> Result<(), bincode::error::DecodeError> {
    // The call the command-line tool makes after its digest check.
    bincode::serde::decode_from_slice::<CompressionVerifierKey<UniformCircuit>, _>(
        bytes,
        bincode::config::legacy(),
    )
    .map(|_| ())
}

#[test]
fn decoders_reject_hostile_bytes_within_a_fixed_memory_limit() {
    let valid = shortest_valid_proof();
    let (status, peak) = measure(|| sealed::decode_proof(&valid));
    assert_eq!(status, DecodeStatus::Accepted, "valid proof encoding");
    assert!(peak <= PROOF_PEAK_LIMIT, "valid proof used {peak} bytes");

    let mut changed = valid.clone().into_bytes();
    let middle = changed.len() / 2;
    changed[middle] = b'!';
    let changed = String::from_utf8(changed).unwrap();
    let mut texts = vec![
        ("one-byte proof text change".to_owned(), changed),
        ("truncated proof".to_owned(), valid[..valid.len() - 1].to_owned()),
    ];
    let streams = hostile_streams();
    for (name, bytes) in &streams {
        texts.push((name.clone(), URL_SAFE_NO_PAD.encode(bytes)));
    }
    for (name, text) in &texts {
        let (status, peak) = measure(|| sealed::decode_proof(text));
        assert_eq!(status, DecodeStatus::Rejected, "proof: {name}");
        assert!(peak <= PROOF_PEAK_LIMIT, "proof: {name} used {peak} bytes");
    }

    for (name, bytes) in &streams {
        let (status, peak) = measure(|| decode_key(bytes));
        assert_ne!(status, DecodeStatus::Panicked, "key: {name}");
        assert!(peak <= KEY_PEAK_LIMIT, "key: {name} used {peak} bytes");
    }
}
