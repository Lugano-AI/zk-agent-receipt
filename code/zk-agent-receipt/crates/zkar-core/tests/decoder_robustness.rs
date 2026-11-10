use std::{
    alloc::{GlobalAlloc, Layout, System},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::atomic::{AtomicUsize, Ordering},
};
use zkar_core::statement::SealedReceipt;

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

fn seeded_text(seed: u64, length: usize) -> String {
    let mut state = seed;
    let mut text = String::with_capacity(length + 1);
    text.push('!');
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        text.push((b' '.saturating_add((state as u8) % 95)) as char);
    }
    text
}

fn valid_receipt() -> String {
    "{\"profile\":\"sar-zk-v0.4b\",\"public_input\":{\"profile\":\"sar-zk-v0.4b\",\"issuer_key_commitment\":\"1\",\"log_root\":\"42\",\"tree_size\":\"17\",\"log_id\":\"log.1\",\"log_head_signature\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"policy_commitment\":\"7\",\"nullifier_scope\":\"5\",\"nullifier\":\"9\"},\"proof\":\"AAAA\",\"fold_count\":\"4\",\"algorithm\":{\"arithmetization\":\"r1cs-nova-uniform\",\"curve\":\"pasta\",\"proof_encoding\":\"nova-snark-0.76.0/bincode-2.0.1-legacy\",\"vk_digest\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}".to_owned()
}

fn escaped_prefix(prefix: u64) -> String {
    prefix
        .to_le_bytes()
        .iter()
        .map(|byte| format!("\\u{byte:04x}"))
        .collect()
}

fn error_bound(input_len: usize) -> usize {
    // The parser stores strings and a small JSON tree. The bound allows four
    // input copies plus one 64 KiB input block.
    input_len.saturating_mul(4).saturating_add(64 * 1024)
}

fn assert_rejected(name: &str, input: &str) {
    let (status, peak) = measure(|| SealedReceipt::parse(input));
    assert_eq!(status, DecodeStatus::Rejected, "{name}");
    assert!(
        peak <= error_bound(input.len()),
        "{name} used {peak} bytes for {} bytes of input",
        input.len()
    );
}

#[test]
fn strict_receipt_parser_rejects_hostile_inputs_with_bounded_allocation() {
    let valid = valid_receipt();
    let (status, peak) = measure(|| SealedReceipt::parse(&valid));
    assert_eq!(status, DecodeStatus::Accepted, "valid receipt");
    assert!(
        peak <= error_bound(valid.len()),
        "valid receipt used {peak} bytes for {} bytes of input",
        valid.len()
    );

    let mut changed = valid.clone().into_bytes();
    let proof_start = valid.find("AAAA").unwrap();
    changed[proof_start] = b'!';
    let changed = String::from_utf8(changed).unwrap();
    assert_rejected("one-byte receipt change", &changed);
    assert_rejected("truncated receipt", &valid[..valid.len() - 1]);

    for (case, length) in [0usize, 1, 7, 8, 31, 64, 511, 4096]
        .into_iter()
        .enumerate()
    {
        let input = seeded_text(0xbb67_ae85_84ca_a73b ^ case as u64, length);
        assert_rejected("seeded random receipt text", &input);
    }

    for prefix in [1_u64 << 32, 1_u64 << 40, u64::MAX] {
        let encoded_prefix = escaped_prefix(prefix);
        let input = valid.replacen("AAAA", &encoded_prefix, 1);
        assert_rejected("bincode length prefix in receipt proof", &input);
    }
}
