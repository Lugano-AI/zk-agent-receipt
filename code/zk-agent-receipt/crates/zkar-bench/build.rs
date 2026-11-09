use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::PathBuf;

const REPORTED_CRATES: &[&str] = &[
    "bincode",
    "ff",
    "group",
    "halo2_poseidon",
    "halo2curves",
    "libc",
    "nova-snark",
    "pasta_curves",
    "rayon",
    "rand_chacha",
    "rand_core",
    "serde",
    "serde_json",
    "zkar-bench",
    "zkar-circuit",
    "zkar-core",
    "zkar-prover",
];

fn main() {
    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Cargo sets manifest dir"));
    let lockfile = manifest_dir.join("../..").join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());

    let lock = fs::read_to_string(&lockfile)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", lockfile.display()));
    let versions = lock_versions(&lock);
    let rendered = REPORTED_CRATES
        .iter()
        .flat_map(|name| {
            let versions = versions.get(*name).unwrap_or_else(|| {
                panic!(
                    "{name} is absent from Cargo.lock; benchmark metadata must name exact versions"
                )
            });
            versions
                .iter()
                .map(|version| format!("{name}@{version}={version}"))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .join(";");

    println!("cargo:rustc-env=ZKAR_BENCH_CRATE_VERSIONS={rendered}");
    println!(
        "cargo:rustc-env=ZKAR_BENCH_TARGET={}",
        env::var("TARGET").expect("Cargo sets target")
    );
    println!(
        "cargo:rustc-env=ZKAR_BENCH_PROFILE={}",
        env::var("PROFILE").expect("Cargo sets profile")
    );
}

fn lock_versions(lock: &str) -> BTreeMap<String, BTreeSet<String>> {
    lock.split("[[package]]")
        .filter_map(|package| {
            let name = package.lines().find_map(|line| {
                line.strip_prefix("name = \"")
                    .and_then(|value| value.strip_suffix('\"'))
            })?;
            let version = package.lines().find_map(|line| {
                line.strip_prefix("version = \"")
                    .and_then(|value| value.strip_suffix('\"'))
            })?;
            Some((name.to_owned(), version.to_owned()))
        })
        .fold(BTreeMap::new(), |mut versions, (name, version)| {
            versions
                .entry(name)
                .or_insert_with(BTreeSet::new)
                .insert(version);
            versions
        })
}
