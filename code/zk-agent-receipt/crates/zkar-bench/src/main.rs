//! Fresh-process, arm64 release benchmark driver for SAR-ZK proof systems.
//!
//! The worker process prints exactly one JSON object on stdout.  The coordinator
//! keeps stdout reserved for that protocol and writes the human and machine
//! reports only after it has collected actual worker results.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "zkar-bench-results-v1";
const FIXTURE_SEED: u64 = 0x5341_525a_4b04_000b;
const CONFIGURATION_TIMEOUT: Duration = Duration::from_secs(90 * 60);
const SYSTEMS: &[&str] = &["folded", "monolithic", "per-entry"];

type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
struct AppError {
    message: String,
}

impl AppError {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for AppError {}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::message(error.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::message(error.to_string())
    }
}

#[derive(Debug)]
enum Invocation {
    Help,
    Coordinator(CoordinatorArgs),
    Worker(WorkerArgs),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CoordinatorArgs {
    ts: Vec<usize>,
    repetitions: usize,
    output_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerArgs {
    system: String,
    t: usize,
    repetition: usize,
    fixture_seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResultsReport {
    schema_version: String,
    run_started_at_utc: String,
    generated_at_utc: String,
    metadata: ReportMetadata,
    methodology: Methodology,
    configurations: Vec<ConfigurationResult>,
    raw_results: Vec<RawResult>,
    summaries: Vec<SummaryResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReportMetadata {
    target_triple: String,
    build_profile: String,
    architecture: String,
    operating_system: String,
    cpu: ObservedField,
    total_cores: ObservedField,
    memory: ObservedField,
    rustc: String,
    rayon_threads: usize,
    rayon_num_threads_environment: Option<String>,
    crate_versions: BTreeMap<String, String>,
    proof_size_encoding: String,
    peak_rss_unit: String,
    source_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObservedField {
    value: Option<String>,
    source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Methodology {
    fixture_seed: String,
    fixture_seed_scope: String,
    requested_t_values: Vec<usize>,
    requested_repetitions: usize,
    configuration_timeout_seconds: u64,
    process_isolation: String,
    candidate_set_reporting: String,
    baseline_limitations: Vec<String>,
    per_entry_baseline_methodology: String,
    extrapolation_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigurationResult {
    system: String,
    t: usize,
    requested_repetitions: usize,
    completed_repetitions: usize,
    status: ConfigurationStatus,
    elapsed_seconds: f64,
    estimate: Option<MeasuredExtrapolation>,
    error: Option<String>,
    worker_artifacts: Vec<WorkerArtifacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerArtifacts {
    repetition: usize,
    stdout_path: String,
    stderr_path: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConfigurationStatus {
    Measured,
    SkippedByMeasuredExtrapolation,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MeasuredExtrapolation {
    source_system: String,
    source_t: usize,
    source_completed_repetitions: usize,
    source_median_wall_seconds_per_repetition: f64,
    target_t: usize,
    target_repetitions: usize,
    estimated_total_seconds: f64,
    method: String,
    label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawResult {
    system: String,
    t: usize,
    repetition: usize,
    fixture_seed: String,
    setup_seconds: f64,
    recursive_proving_seconds: Option<f64>,
    compression_seconds: Option<f64>,
    total_proving_seconds: f64,
    verification_seconds: f64,
    bincode_proof_bytes: usize,
    peak_rss_bytes: u64,
    wall_seconds: f64,
    proof_count: usize,
    per_proof_setup_seconds: Vec<f64>,
    per_proof_bincode_bytes: Vec<usize>,
    per_proof_proving_seconds: Vec<f64>,
    per_proof_verification_seconds: Vec<f64>,
    constraint_counts: ConstraintCounts,
    folds: usize,
    log_leaves: usize,
    candidate_set_size: usize,
    candidate_set_assessment: String,
    per_entry_totals: Option<PerEntryTotals>,
    worker_stdout_path: String,
    worker_stderr_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConstraintCounts {
    uniform_application_constraints: usize,
    primary_constraints: usize,
    secondary_constraints: usize,
    monolithic_constraints: Option<usize>,
    standalone_start_constraints: usize,
    standalone_step_constraints: usize,
    standalone_final_constraints: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerEntryTotals {
    proof_count: usize,
    setup_seconds: f64,
    proving_seconds: f64,
    verification_seconds: f64,
    bincode_proof_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SummaryResult {
    system: String,
    t: usize,
    status: ConfigurationStatus,
    requested_repetitions: usize,
    completed_repetitions: usize,
    medians: MetricMedians,
    per_entry: Option<PerEntrySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct MetricMedians {
    setup_seconds: Option<f64>,
    recursive_proving_seconds: Option<f64>,
    compression_seconds: Option<f64>,
    total_proving_seconds: Option<f64>,
    verification_seconds: Option<f64>,
    bincode_proof_bytes: Option<f64>,
    peak_rss_bytes: Option<f64>,
    wall_seconds: Option<f64>,
    proof_count: Option<f64>,
    uniform_application_constraints: Option<f64>,
    primary_constraints: Option<f64>,
    secondary_constraints: Option<f64>,
    monolithic_constraints: Option<f64>,
    standalone_start_constraints: Option<f64>,
    standalone_step_constraints: Option<f64>,
    standalone_final_constraints: Option<f64>,
    folds: Option<f64>,
    log_leaves: Option<f64>,
    candidate_set_size: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerEntrySummary {
    total_setup_seconds: Option<f64>,
    total_proving_seconds: Option<f64>,
    total_verification_seconds: Option<f64>,
    total_bincode_proof_bytes: Option<f64>,
    per_proof_medians: Vec<PerProofMedian>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PerProofMedian {
    proof_index: usize,
    setup_seconds: Option<f64>,
    proving_seconds: Option<f64>,
    verification_seconds: Option<f64>,
    bincode_proof_bytes: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WorkerResult {
    schema_version: String,
    system: String,
    t: usize,
    repetition: usize,
    fixture_seed: String,
    measurement: zkar_prover::benchmark::Measurement,
    peak_rss_bytes: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("zkar-bench: {error}");
        process::exit(1);
    }
}

fn run() -> AppResult<()> {
    match parse_invocation(env::args().skip(1))? {
        Invocation::Help => {
            print_usage();
            Ok(())
        }
        Invocation::Coordinator(args) => run_coordinator(args),
        Invocation::Worker(args) => run_worker(args),
    }
}

fn parse_invocation(arguments: impl IntoIterator<Item = String>) -> AppResult<Invocation> {
    let mut arguments = arguments.into_iter().peekable();
    if arguments.peek().is_none() {
        return Err(AppError::message(
            "missing arguments; pass --help for usage",
        ));
    }

    let mut worker = false;
    let mut t_value = None;
    let mut repetitions = None;
    let mut output_dir = None;
    let mut system = None;
    let mut repetition = None;
    let mut fixture_seed = None;

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--help" | "-h" => return Ok(Invocation::Help),
            "--worker" => worker = true,
            "--t" => {
                t_value = Some(next_value(&mut arguments, "--t")?);
            }
            "--reps" => {
                repetitions = Some(parse_nonzero_usize(
                    &next_value(&mut arguments, "--reps")?,
                    "--reps",
                )?);
            }
            "--out" => output_dir = Some(PathBuf::from(next_value(&mut arguments, "--out")?)),
            "--system" => system = Some(next_value(&mut arguments, "--system")?),
            "--rep" => {
                repetition = Some(parse_usize(&next_value(&mut arguments, "--rep")?, "--rep")?);
            }
            "--seed" => {
                fixture_seed = Some(parse_u64(&next_value(&mut arguments, "--seed")?, "--seed")?)
            }
            unknown => {
                return Err(AppError::message(format!(
                    "unknown argument {unknown:?}; pass --help for usage"
                )))
            }
        }
    }

    if worker {
        let system = system.ok_or_else(|| AppError::message("--worker requires --system"))?;
        if !SYSTEMS.contains(&system.as_str()) {
            return Err(AppError::message(format!(
                "unsupported --system {system:?}"
            )));
        }
        return Ok(Invocation::Worker(WorkerArgs {
            system,
            t: parse_t(&t_value.ok_or_else(|| AppError::message("--worker requires --t"))?)?,
            repetition: repetition.ok_or_else(|| AppError::message("--worker requires --rep"))?,
            fixture_seed: fixture_seed
                .ok_or_else(|| AppError::message("--worker requires --seed"))?,
        }));
    }

    if system.is_some() || repetition.is_some() || fixture_seed.is_some() {
        return Err(AppError::message(
            "--system, --rep, and --seed are internal worker arguments; omit them from coordinator runs",
        ));
    }

    Ok(Invocation::Coordinator(CoordinatorArgs {
        ts: parse_t_list(&t_value.ok_or_else(|| AppError::message("coordinator requires --t"))?)?,
        repetitions: repetitions.ok_or_else(|| AppError::message("coordinator requires --reps"))?,
        output_dir: output_dir.ok_or_else(|| AppError::message("coordinator requires --out"))?,
    }))
}

fn next_value<I>(arguments: &mut I, option: &str) -> AppResult<String>
where
    I: Iterator<Item = String>,
{
    arguments
        .next()
        .ok_or_else(|| AppError::message(format!("{option} needs a value")))
}

fn parse_t_list(value: &str) -> AppResult<Vec<usize>> {
    if value.is_empty() {
        return Err(AppError::message("--t must list one or more values"));
    }
    let mut values = BTreeSet::new();
    for item in value.split(',') {
        values.insert(parse_t(item)?);
    }
    Ok(values.into_iter().collect())
}

fn parse_t(value: &str) -> AppResult<usize> {
    let t = value.parse::<u64>().map_err(|_| {
        AppError::message(format!("--t must be an unsigned integer, got {value:?}"))
    })?;
    if t == 0 || t >= (1_u64 << 32) {
        return Err(AppError::message("--t must satisfy 1 <= T < 2^32"));
    }
    usize::try_from(t).map_err(|_| AppError::message("--t does not fit this target usize"))
}

fn parse_nonzero_usize(value: &str, option: &str) -> AppResult<usize> {
    let parsed = parse_usize(value, option)?;
    if parsed == 0 {
        return Err(AppError::message(format!(
            "{option} must be greater than zero"
        )));
    }
    Ok(parsed)
}

fn parse_usize(value: &str, option: &str) -> AppResult<usize> {
    value.parse().map_err(|_| {
        AppError::message(format!(
            "{option} must be an unsigned integer, got {value:?}"
        ))
    })
}

fn parse_u64(value: &str, option: &str) -> AppResult<u64> {
    let parsed = value
        .strip_prefix("0x")
        .map(|hex| u64::from_str_radix(hex, 16))
        .unwrap_or_else(|| value.parse());
    parsed.map_err(|_| AppError::message(format!("{option} must be a u64, got {value:?}")))
}

fn format_seed(seed: u64) -> String {
    format!("0x{seed:016x}")
}

fn print_usage() {
    println!(
        "Usage: zkar-bench --t 10,100,1000 --reps 3 --out PATH\n\
         \n\
         Runs every system/T/repetition in a fresh release arm64 child process.\n\
         PATH is a directory; results.json and results.md are written there."
    );
}

fn run_coordinator(arguments: CoordinatorArgs) -> AppResult<()> {
    require_release_arm64()?;
    let raw_output_dir = arguments.output_dir.join("raw");
    fs::create_dir_all(&raw_output_dir)?;
    let run_started_at_utc = utc_now();
    let metadata = collect_metadata();
    let methodology = Methodology {
        fixture_seed: format_seed(FIXTURE_SEED),
        fixture_seed_scope: "Fixture generation only; the prover retains its own fresh proof randomness.".to_owned(),
        requested_t_values: arguments.ts.clone(),
        requested_repetitions: arguments.repetitions,
        configuration_timeout_seconds: CONFIGURATION_TIMEOUT.as_secs(),
        process_isolation: "Each system/T/repetition is a newly spawned child process; peak RSS therefore belongs to that one worker process.".to_owned(),
        candidate_set_reporting: "The reported candidate-set size is a structural fixture count: 16 synthetic receipts with the same issuer, policy, and public bucket. It is weak, separate from log leaves, and not a measured deployment anonymity set. The published deterministic fixture seed exposes fixture witnesses, so these benchmarks make no anonymity or privacy demonstration.".to_owned(),
        baseline_limitations: vec![
            "Direct Spartan baseline APIs do not add the random satisfying-instance fold required for the profile zero-knowledge construction; no zero-knowledge guarantee is claimed for those baselines.".to_owned(),
            "The per-entry baseline lacks authenticated chaining and the secure-receipt start/end composition; it is intentionally cheaper than a secure composition.".to_owned(),
        ],
        per_entry_baseline_methodology: "The per-entry baseline emits T+1 proofs: a combined START plus first STEP proof, generic STEP proofs, and a FINAL proof. Setup creates each distinct shape/key once (two shapes when T=1); raw per-proof setup charges that cost to the first proof using that shape and records zero for reuse.".to_owned(),
        extrapolation_policy: "A configuration may be skipped only when a smaller completed configuration for the same system yields a measured linear T extrapolation above the 90-minute all-repetitions budget. Such a record is explicitly labeled an estimate and contains no invented measurement metrics.".to_owned(),
    };

    let mut configurations = Vec::new();
    let mut raw_results = Vec::new();
    for &system in SYSTEMS {
        for &t in &arguments.ts {
            let estimate = estimate_configuration(
                system,
                t,
                arguments.repetitions,
                &configurations,
                &raw_results,
            );
            if estimate.as_ref().is_some_and(|estimate| {
                estimate.estimated_total_seconds > CONFIGURATION_TIMEOUT.as_secs_f64()
            }) {
                let estimate = estimate.expect("checked above");
                eprintln!(
                    "[zkar-bench] skipping {system} T={t}: measured extrapolation estimates {:.1}s for {} repetitions (> {}s)",
                    estimate.estimated_total_seconds,
                    arguments.repetitions,
                    CONFIGURATION_TIMEOUT.as_secs()
                );
                configurations.push(ConfigurationResult {
                    system: system.to_owned(),
                    t,
                    requested_repetitions: arguments.repetitions,
                    completed_repetitions: 0,
                    status: ConfigurationStatus::SkippedByMeasuredExtrapolation,
                    elapsed_seconds: 0.0,
                    estimate: Some(estimate),
                    error: None,
                    worker_artifacts: Vec::new(),
                });
                checkpoint_report(
                    &arguments.output_dir,
                    &run_started_at_utc,
                    &metadata,
                    &methodology,
                    &configurations,
                    &raw_results,
                )?;
                continue;
            }

            let configuration = run_configuration(
                system,
                t,
                arguments.repetitions,
                FIXTURE_SEED,
                &raw_output_dir,
            );
            raw_results.extend(configuration.raw_results);
            configurations.push(configuration.result);
            checkpoint_report(
                &arguments.output_dir,
                &run_started_at_utc,
                &metadata,
                &methodology,
                &configurations,
                &raw_results,
            )?;
        }
    }

    let report = make_report(
        &run_started_at_utc,
        metadata,
        methodology,
        configurations,
        raw_results,
    );
    write_reports(&arguments.output_dir, &report)?;

    if let Some(configuration) = report.configurations.iter().find(|configuration| {
        matches!(
            configuration.status,
            ConfigurationStatus::TimedOut | ConfigurationStatus::Failed
        )
    }) {
        return Err(AppError::message(format!(
            "benchmark report was written, but {} T={} finished with status {:?}",
            configuration.system, configuration.t, configuration.status
        )));
    }
    Ok(())
}

fn checkpoint_report(
    output_dir: &Path,
    run_started_at_utc: &str,
    metadata: &ReportMetadata,
    methodology: &Methodology,
    configurations: &[ConfigurationResult],
    raw_results: &[RawResult],
) -> AppResult<()> {
    let report = make_report(
        run_started_at_utc,
        metadata.clone(),
        methodology.clone(),
        configurations.to_vec(),
        raw_results.to_vec(),
    );
    write_reports(output_dir, &report)
}

fn make_report(
    run_started_at_utc: &str,
    metadata: ReportMetadata,
    methodology: Methodology,
    configurations: Vec<ConfigurationResult>,
    raw_results: Vec<RawResult>,
) -> ResultsReport {
    let summaries = build_summaries(&configurations, &raw_results);
    ResultsReport {
        schema_version: SCHEMA_VERSION.to_owned(),
        run_started_at_utc: run_started_at_utc.to_owned(),
        generated_at_utc: utc_now(),
        metadata,
        methodology,
        configurations,
        raw_results,
        summaries,
    }
}

struct ConfigurationRun {
    result: ConfigurationResult,
    raw_results: Vec<RawResult>,
}

fn run_configuration(
    system: &str,
    t: usize,
    repetitions: usize,
    fixture_seed: u64,
    raw_output_dir: &Path,
) -> ConfigurationRun {
    let started = Instant::now();
    let mut raw_results = Vec::new();
    let mut status = ConfigurationStatus::Measured;
    let mut error = None;
    let mut worker_artifacts = Vec::new();

    for repetition in 0..repetitions {
        let remaining = CONFIGURATION_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            status = ConfigurationStatus::TimedOut;
            error = Some(format!(
                "configuration exceeded the {}-second budget before repetition {} could start",
                CONFIGURATION_TIMEOUT.as_secs(),
                repetition
            ));
            break;
        }

        eprintln!(
            "[zkar-bench] starting {system} T={t} repetition {}/{} (fresh child; {:.0}s configuration budget remains)",
            repetition + 1,
            repetitions,
            remaining.as_secs_f64()
        );
        match run_worker_process(
            system,
            t,
            repetition,
            fixture_seed,
            remaining,
            raw_output_dir,
        ) {
            Ok(worker_run) => {
                worker_artifacts.push(worker_run.artifacts.clone());
                match raw_from_worker(worker_run) {
                    Ok(raw) => raw_results.push(raw),
                    Err(worker_error) => {
                        status = ConfigurationStatus::Failed;
                        error = Some(worker_error.to_string());
                        break;
                    }
                }
            }
            Err(WorkerProcessError::TimedOut) => {
                worker_artifacts.push(worker_artifacts_for(raw_output_dir, system, t, repetition));
                status = ConfigurationStatus::TimedOut;
                error = Some(format!(
                    "worker exceeded the remaining {:.3}-second configuration budget at repetition {}",
                    remaining.as_secs_f64(),
                    repetition
                ));
                break;
            }
            Err(WorkerProcessError::Failed(worker_error)) => {
                worker_artifacts.push(worker_artifacts_for(raw_output_dir, system, t, repetition));
                status = ConfigurationStatus::Failed;
                error = Some(worker_error.to_string());
                break;
            }
        }
    }

    ConfigurationRun {
        result: ConfigurationResult {
            system: system.to_owned(),
            t,
            requested_repetitions: repetitions,
            completed_repetitions: raw_results.len(),
            status,
            elapsed_seconds: started.elapsed().as_secs_f64(),
            estimate: None,
            error,
            worker_artifacts,
        },
        raw_results,
    }
}

#[derive(Debug)]
enum WorkerProcessError {
    TimedOut,
    Failed(AppError),
}

struct WorkerRun {
    worker: WorkerResult,
    wall_seconds: f64,
    artifacts: WorkerArtifacts,
}

fn run_worker_process(
    system: &str,
    t: usize,
    repetition: usize,
    fixture_seed: u64,
    timeout: Duration,
    raw_output_dir: &Path,
) -> Result<WorkerRun, WorkerProcessError> {
    let executable =
        env::current_exe().map_err(|error| WorkerProcessError::Failed(error.into()))?;
    let started = Instant::now();
    let artifacts = worker_artifacts_for(raw_output_dir, system, t, repetition);
    let stdout_file =
        File::create(raw_output_dir.join(artifact_file_name(system, t, repetition, "stdout")))
            .map_err(|error| WorkerProcessError::Failed(error.into()))?;
    let stderr_file =
        File::create(raw_output_dir.join(artifact_file_name(system, t, repetition, "stderr")))
            .map_err(|error| WorkerProcessError::Failed(error.into()))?;
    let mut child = Command::new(executable)
        .args([
            "--worker".to_owned(),
            "--system".to_owned(),
            system.to_owned(),
            "--t".to_owned(),
            t.to_string(),
            "--rep".to_owned(),
            repetition.to_string(),
            "--seed".to_owned(),
            format_seed(fixture_seed),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| WorkerProcessError::Failed(error.into()))?;

    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(WorkerProcessError::Failed(AppError::message(
            "worker stdout was not captured",
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(WorkerProcessError::Failed(AppError::message(
            "worker stderr was not captured",
        )));
    };
    let stdout_capture = capture_stream(stdout, stdout_file, false);
    let stderr_capture = capture_stream(stderr, stderr_file, true);

    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = finish_capture(stdout_capture);
                let _ = finish_capture(stderr_capture);
                return Err(WorkerProcessError::TimedOut);
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = finish_capture(stdout_capture);
                let _ = finish_capture(stderr_capture);
                return Err(WorkerProcessError::Failed(error.into()));
            }
        }
    };
    let wall_seconds = started.elapsed().as_secs_f64();
    finish_capture(stdout_capture).map_err(WorkerProcessError::Failed)?;
    finish_capture(stderr_capture).map_err(WorkerProcessError::Failed)?;
    let stdout = fs::read_to_string(
        raw_output_dir.join(artifact_file_name(system, t, repetition, "stdout")),
    )
    .map_err(|error| WorkerProcessError::Failed(error.into()))?;

    if !status.success() {
        return Err(WorkerProcessError::Failed(AppError::message(format!(
            "worker exited with {status}; its diagnostics were written to stderr"
        ))));
    }
    let worker: WorkerResult =
        serde_json::from_str(&stdout).map_err(|error| WorkerProcessError::Failed(error.into()))?;
    if worker.schema_version != SCHEMA_VERSION
        || worker.system != system
        || worker.t != t
        || worker.repetition != repetition
        || worker.fixture_seed != format_seed(fixture_seed)
    {
        return Err(WorkerProcessError::Failed(AppError::message(
            "worker response did not match the requested configuration",
        )));
    }
    Ok(WorkerRun {
        worker,
        wall_seconds,
        artifacts,
    })
}

fn worker_artifacts_for(
    raw_output_dir: &Path,
    system: &str,
    t: usize,
    repetition: usize,
) -> WorkerArtifacts {
    let _ = raw_output_dir;
    WorkerArtifacts {
        repetition,
        stdout_path: format!(
            "raw/{}",
            artifact_file_name(system, t, repetition, "stdout")
        ),
        stderr_path: format!(
            "raw/{}",
            artifact_file_name(system, t, repetition, "stderr")
        ),
    }
}

fn artifact_file_name(system: &str, t: usize, repetition: usize, stream: &str) -> String {
    let system = system
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    format!("{system}-t{t}-rep{repetition}.{stream}.txt")
}

fn capture_stream<R>(
    mut stream: R,
    mut file: File,
    echo_to_parent_stderr: bool,
) -> thread::JoinHandle<Result<(), String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = [0_u8; 8 * 1024];
        let mut first_error = None;
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(length) => {
                    if let Err(error) = file.write_all(&buffer[..length]) {
                        first_error
                            .get_or_insert_with(|| format!("cannot write worker capture: {error}"));
                    }
                    if echo_to_parent_stderr {
                        let mut stderr = std::io::stderr().lock();
                        if let Err(error) = stderr.write_all(&buffer[..length]) {
                            first_error.get_or_insert_with(|| {
                                format!("cannot echo worker stderr: {error}")
                            });
                        }
                    }
                }
                Err(error) => {
                    first_error
                        .get_or_insert_with(|| format!("cannot read worker stream: {error}"));
                    break;
                }
            }
        }
        if let Err(error) = file.flush() {
            first_error.get_or_insert_with(|| format!("cannot flush worker capture: {error}"));
        }
        first_error.map_or(Ok(()), Err)
    })
}

fn finish_capture(handle: thread::JoinHandle<Result<(), String>>) -> Result<(), AppError> {
    match handle.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(AppError::message(error)),
        Err(_) => Err(AppError::message("worker capture thread panicked")),
    }
}

fn run_worker(arguments: WorkerArgs) -> AppResult<()> {
    require_release_arm64()?;
    let measurement =
        zkar_prover::benchmark::measure(arguments.t, &arguments.system, arguments.fixture_seed)
            .map_err(|error| AppError::message(format!("prover measurement failed: {error}")))?;
    let worker = WorkerResult {
        schema_version: SCHEMA_VERSION.to_owned(),
        system: arguments.system,
        t: arguments.t,
        repetition: arguments.repetition,
        fixture_seed: format_seed(arguments.fixture_seed),
        measurement,
        peak_rss_bytes: peak_rss_bytes()?,
    };
    println!("{}", serde_json::to_string(&worker)?);
    Ok(())
}

fn require_release_arm64() -> AppResult<()> {
    if cfg!(debug_assertions) || !cfg!(target_arch = "aarch64") || !cfg!(target_os = "macos") {
        return Err(AppError::message(format!(
            "benchmark measurements require a non-debug aarch64-apple-darwin build (built target={}, profile={}, running arch={}, os={})",
            env!("ZKAR_BENCH_TARGET"),
            env!("ZKAR_BENCH_PROFILE"),
            std::env::consts::ARCH,
            std::env::consts::OS,
        )));
    }
    Ok(())
}

fn raw_from_worker(worker_run: WorkerRun) -> AppResult<RawResult> {
    let WorkerRun {
        worker,
        wall_seconds,
        artifacts,
    } = worker_run;
    let measurement = worker.measurement;
    validate_measurement(&measurement)?;

    let per_entry_totals = if worker.system == "per-entry" {
        Some(PerEntryTotals {
            proof_count: measurement.proof_count,
            setup_seconds: sum_f64(&measurement.per_proof_setup_seconds)?,
            proving_seconds: sum_f64(&measurement.per_proof_prover_seconds)?,
            verification_seconds: sum_f64(&measurement.per_proof_verifier_seconds)?,
            bincode_proof_bytes: sum_usize(&measurement.per_proof_bytes)?,
        })
    } else {
        None
    };
    let candidate_set_assessment = if measurement.candidate_set_size <= 16 {
        format!(
            "weak structural fixture count: {} synthetic receipts share issuer, policy, and public bucket; the deterministic published fixture seed exposes witnesses, so this is not an anonymity or privacy demonstration",
            measurement.candidate_set_size
        )
    } else {
        "structural fixture count only; it is distinct from log leaves, not inferred from tree size, and not a deployment anonymity or privacy measurement".to_owned()
    };

    Ok(RawResult {
        system: worker.system,
        t: worker.t,
        repetition: worker.repetition,
        fixture_seed: worker.fixture_seed,
        setup_seconds: measurement.setup_seconds,
        recursive_proving_seconds: measurement.recursive_seconds,
        compression_seconds: measurement.compression_seconds,
        total_proving_seconds: measurement.prover_seconds,
        verification_seconds: measurement.verifier_seconds,
        bincode_proof_bytes: measurement.proof_bytes,
        peak_rss_bytes: worker.peak_rss_bytes,
        wall_seconds,
        proof_count: measurement.proof_count,
        per_proof_setup_seconds: measurement.per_proof_setup_seconds,
        per_proof_bincode_bytes: measurement.per_proof_bytes,
        per_proof_proving_seconds: measurement.per_proof_prover_seconds,
        per_proof_verification_seconds: measurement.per_proof_verifier_seconds,
        constraint_counts: ConstraintCounts {
            uniform_application_constraints: measurement.uniform_constraints,
            primary_constraints: measurement.primary_constraints,
            secondary_constraints: measurement.secondary_constraints,
            monolithic_constraints: measurement.monolithic_constraints,
            standalone_start_constraints: measurement.branch_constraints[0],
            standalone_step_constraints: measurement.branch_constraints[1],
            standalone_final_constraints: measurement.branch_constraints[2],
        },
        folds: measurement.folds,
        log_leaves: measurement.log_leaves,
        candidate_set_size: measurement.candidate_set_size,
        candidate_set_assessment,
        per_entry_totals,
        worker_stdout_path: artifacts.stdout_path,
        worker_stderr_path: artifacts.stderr_path,
    })
}

fn validate_measurement(measurement: &zkar_prover::benchmark::Measurement) -> AppResult<()> {
    for (name, value) in [
        ("setup_seconds", measurement.setup_seconds),
        ("prover_seconds", measurement.prover_seconds),
        ("verifier_seconds", measurement.verifier_seconds),
    ] {
        validate_nonnegative_finite(name, value)?;
    }
    for (name, value) in [
        ("recursive_seconds", measurement.recursive_seconds),
        ("compression_seconds", measurement.compression_seconds),
    ] {
        if let Some(value) = value {
            validate_nonnegative_finite(name, value)?;
        }
    }
    for (name, values) in [
        (
            "per_proof_setup_seconds",
            &measurement.per_proof_setup_seconds,
        ),
        (
            "per_proof_prover_seconds",
            &measurement.per_proof_prover_seconds,
        ),
        (
            "per_proof_verifier_seconds",
            &measurement.per_proof_verifier_seconds,
        ),
    ] {
        if values.len() != measurement.proof_count {
            return Err(AppError::message(format!(
                "measurement {name} has {} values but proof_count is {}",
                values.len(),
                measurement.proof_count
            )));
        }
        for value in values {
            validate_nonnegative_finite(name, *value)?;
        }
    }
    if measurement.per_proof_bytes.len() != measurement.proof_count {
        return Err(AppError::message(format!(
            "measurement per_proof_bytes has {} values but proof_count is {}",
            measurement.per_proof_bytes.len(),
            measurement.proof_count
        )));
    }
    if measurement.proof_count == 0 {
        return Err(AppError::message("measurement proof_count must be nonzero"));
    }
    Ok(())
}

fn validate_nonnegative_finite(name: &str, value: f64) -> AppResult<()> {
    if !value.is_finite() || value < 0.0 {
        return Err(AppError::message(format!(
            "measurement {name} must be a finite nonnegative number, got {value}"
        )));
    }
    Ok(())
}

fn sum_f64(values: &[f64]) -> AppResult<f64> {
    let total: f64 = values.iter().sum();
    validate_nonnegative_finite("per-proof total", total)?;
    Ok(total)
}

fn sum_usize(values: &[usize]) -> AppResult<usize> {
    values.iter().try_fold(0_usize, |total, value| {
        total
            .checked_add(*value)
            .ok_or_else(|| AppError::message("per-proof byte total overflowed usize"))
    })
}

fn estimate_configuration(
    system: &str,
    target_t: usize,
    target_repetitions: usize,
    configurations: &[ConfigurationResult],
    raw_results: &[RawResult],
) -> Option<MeasuredExtrapolation> {
    let source = configurations
        .iter()
        .filter(|configuration| {
            configuration.system == system
                && configuration.status == ConfigurationStatus::Measured
                && configuration.t < target_t
                && configuration.completed_repetitions > 0
        })
        .max_by_key(|configuration| configuration.t)?;
    let source_wall_seconds = raw_results
        .iter()
        .filter(|result| result.system == system && result.t == source.t)
        .collect::<Vec<_>>();
    let source_median_wall_seconds_per_repetition = median_f64(
        source_wall_seconds
            .iter()
            .map(|result| result.wall_seconds)
            .collect(),
    )?;
    let (estimated_per_repetition, method) = match system {
        "folded" => {
            let source_bucket = folding_bucket(source.t)? as f64;
            let target_bucket = folding_bucket(target_t)? as f64;
            let estimates = source_wall_seconds
                .iter()
                .map(|result| {
                    let recursive = result.recursive_proving_seconds?;
                    let compression = result.compression_seconds?;
                    let fixed = result.setup_seconds + compression + result.verification_seconds;
                    let residual = (result.wall_seconds - fixed - recursive).max(0.0);
                    Some(fixed + recursive * (target_bucket / source_bucket) + residual)
                })
                .collect::<Option<Vec<_>>>()?;
            (
                median_f64(estimates)?,
                "folded estimate: holds setup, compression, verification, and observed process residual fixed; scales recursive proving by next_power_of_two(T + 2), the public folding bucket".to_owned(),
            )
        }
        "per-entry" => {
            let proof_ratio = (target_t + 1) as f64 / (source.t + 1) as f64;
            let residual_ratio = target_t as f64 / source.t as f64;
            let estimates = source_wall_seconds
                .iter()
                .map(|result| {
                    let variable = result.total_proving_seconds + result.verification_seconds;
                    let residual = (result.wall_seconds - result.setup_seconds - variable).max(0.0);
                    result.setup_seconds + variable * proof_ratio + residual * residual_ratio
                })
                .collect::<Vec<_>>();
            (
                median_f64(estimates)?,
                "per-entry estimate: holds setup fixed; scales aggregate proving plus verification by (T + 1), the proof count; scales remaining observed wall overhead linearly in T as a conservative heuristic".to_owned(),
            )
        }
        "monolithic" => {
            let estimates = source_wall_seconds
                .iter()
                .map(|result| result.wall_seconds * (target_t as f64 / source.t as f64))
                .collect::<Vec<_>>();
            (
                median_f64(estimates)?,
                "monolithic estimate: scales complete measured wall time linearly in T; this is explicitly a heuristic".to_owned(),
            )
        }
        _ => return None,
    };
    let estimated_total_seconds = estimated_per_repetition * target_repetitions as f64;
    Some(MeasuredExtrapolation {
        source_system: system.to_owned(),
        source_t: source.t,
        source_completed_repetitions: source.completed_repetitions,
        source_median_wall_seconds_per_repetition,
        target_t,
        target_repetitions,
        estimated_total_seconds,
        method,
        label: "measured extrapolation only; not a benchmark result".to_owned(),
    })
}

fn folding_bucket(t: usize) -> Option<usize> {
    t.checked_add(2)?.checked_next_power_of_two()
}

fn collect_metadata() -> ReportMetadata {
    let profiler = command_stdout("system_profiler", &["SPHardwareDataType"]);
    let (cpu, total_cores, memory) = match profiler {
        Ok(output) => (
            profiler_field(&output, "Chip", "system_profiler SPHardwareDataType"),
            profiler_field(
                &output,
                "Total Number of Cores",
                "system_profiler SPHardwareDataType",
            ),
            profiler_field(&output, "Memory", "system_profiler SPHardwareDataType"),
        ),
        Err(error) => {
            let source = format!("unavailable: system_profiler SPHardwareDataType failed: {error}");
            (
                ObservedField {
                    value: None,
                    source: source.clone(),
                },
                ObservedField {
                    value: None,
                    source: source.clone(),
                },
                ObservedField {
                    value: None,
                    source,
                },
            )
        }
    };

    ReportMetadata {
        target_triple: env!("ZKAR_BENCH_TARGET").to_owned(),
        build_profile: env!("ZKAR_BENCH_PROFILE").to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        operating_system: std::env::consts::OS.to_owned(),
        cpu,
        total_cores,
        memory,
        rustc: command_stdout("rustc", &["--version"])
            .unwrap_or_else(|error| format!("unavailable: {error}")),
        rayon_threads: rayon::current_num_threads(),
        rayon_num_threads_environment: env::var("RAYON_NUM_THREADS").ok(),
        crate_versions: crate_versions(),
        proof_size_encoding: "bincode 2.0.1 serde legacy encoding, uncompressed; per-entry proof bytes are the sum of individual proof encodings with no container framing".to_owned(),
        peak_rss_unit: "bytes (macOS getrusage(RUSAGE_SELF).ru_maxrss)".to_owned(),
        source_revision: "not collected by design (no git metadata)".to_owned(),
    }
}

fn command_stdout(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn profiler_field(output: &str, field: &str, source: &str) -> ObservedField {
    let prefix = format!("{field}:");
    let value = output
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    ObservedField {
        value,
        source: source.to_owned(),
    }
}

fn crate_versions() -> BTreeMap<String, String> {
    env!("ZKAR_BENCH_CRATE_VERSIONS")
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, version)| (name.to_owned(), version.to_owned()))
        .collect()
}

fn utc_now() -> String {
    command_stdout("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|_| {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        format!("unix-seconds:{seconds}")
    })
}

#[cfg(target_os = "macos")]
fn peak_rss_bytes() -> AppResult<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is a valid writable rusage pointer and RUSAGE_SELF is a
    // documented selector. It is initialized by getrusage only on success.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return Err(AppError::message(format!(
            "getrusage(RUSAGE_SELF) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: getrusage returned success above.
    let usage = unsafe { usage.assume_init() };
    u64::try_from(usage.ru_maxrss)
        .map_err(|_| AppError::message("getrusage returned a negative ru_maxrss"))
}

#[cfg(not(target_os = "macos"))]
fn peak_rss_bytes() -> AppResult<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is a valid writable rusage pointer and RUSAGE_SELF is a
    // documented selector. It is initialized by getrusage only on success.
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return Err(AppError::message(format!(
            "getrusage(RUSAGE_SELF) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: getrusage returned success above.
    let usage = unsafe { usage.assume_init() };
    let kibibytes = u64::try_from(usage.ru_maxrss)
        .map_err(|_| AppError::message("getrusage returned a negative ru_maxrss"))?;
    kibibytes
        .checked_mul(1024)
        .ok_or_else(|| AppError::message("ru_maxrss byte conversion overflowed"))
}

fn build_summaries(
    configurations: &[ConfigurationResult],
    raw_results: &[RawResult],
) -> Vec<SummaryResult> {
    configurations
        .iter()
        .map(|configuration| {
            let rows = raw_results
                .iter()
                .filter(|result| {
                    result.system == configuration.system && result.t == configuration.t
                })
                .collect::<Vec<_>>();
            let medians = MetricMedians {
                setup_seconds: median_f64(rows.iter().map(|result| result.setup_seconds).collect()),
                recursive_proving_seconds: median_f64(
                    rows.iter()
                        .filter_map(|result| result.recursive_proving_seconds)
                        .collect(),
                ),
                compression_seconds: median_f64(
                    rows.iter()
                        .filter_map(|result| result.compression_seconds)
                        .collect(),
                ),
                total_proving_seconds: median_f64(
                    rows.iter()
                        .map(|result| result.total_proving_seconds)
                        .collect(),
                ),
                verification_seconds: median_f64(
                    rows.iter()
                        .map(|result| result.verification_seconds)
                        .collect(),
                ),
                bincode_proof_bytes: median_usize(
                    rows.iter()
                        .map(|result| result.bincode_proof_bytes)
                        .collect(),
                ),
                peak_rss_bytes: median_u64(
                    rows.iter().map(|result| result.peak_rss_bytes).collect(),
                ),
                wall_seconds: median_f64(rows.iter().map(|result| result.wall_seconds).collect()),
                proof_count: median_usize(rows.iter().map(|result| result.proof_count).collect()),
                uniform_application_constraints: median_usize(
                    rows.iter()
                        .map(|result| result.constraint_counts.uniform_application_constraints)
                        .collect(),
                ),
                primary_constraints: median_usize(
                    rows.iter()
                        .map(|result| result.constraint_counts.primary_constraints)
                        .collect(),
                ),
                secondary_constraints: median_usize(
                    rows.iter()
                        .map(|result| result.constraint_counts.secondary_constraints)
                        .collect(),
                ),
                monolithic_constraints: median_usize(
                    rows.iter()
                        .filter_map(|result| result.constraint_counts.monolithic_constraints)
                        .collect(),
                ),
                standalone_start_constraints: median_usize(
                    rows.iter()
                        .map(|result| result.constraint_counts.standalone_start_constraints)
                        .collect(),
                ),
                standalone_step_constraints: median_usize(
                    rows.iter()
                        .map(|result| result.constraint_counts.standalone_step_constraints)
                        .collect(),
                ),
                standalone_final_constraints: median_usize(
                    rows.iter()
                        .map(|result| result.constraint_counts.standalone_final_constraints)
                        .collect(),
                ),
                folds: median_usize(rows.iter().map(|result| result.folds).collect()),
                log_leaves: median_usize(rows.iter().map(|result| result.log_leaves).collect()),
                candidate_set_size: median_usize(
                    rows.iter()
                        .map(|result| result.candidate_set_size)
                        .collect(),
                ),
            };
            let per_entry = (configuration.system == "per-entry").then(|| PerEntrySummary {
                total_setup_seconds: median_f64(
                    rows.iter()
                        .filter_map(|result| {
                            result
                                .per_entry_totals
                                .as_ref()
                                .map(|total| total.setup_seconds)
                        })
                        .collect(),
                ),
                total_proving_seconds: median_f64(
                    rows.iter()
                        .filter_map(|result| {
                            result
                                .per_entry_totals
                                .as_ref()
                                .map(|total| total.proving_seconds)
                        })
                        .collect(),
                ),
                total_verification_seconds: median_f64(
                    rows.iter()
                        .filter_map(|result| {
                            result
                                .per_entry_totals
                                .as_ref()
                                .map(|total| total.verification_seconds)
                        })
                        .collect(),
                ),
                total_bincode_proof_bytes: median_usize(
                    rows.iter()
                        .filter_map(|result| {
                            result
                                .per_entry_totals
                                .as_ref()
                                .map(|total| total.bincode_proof_bytes)
                        })
                        .collect(),
                ),
                per_proof_medians: per_proof_medians(&rows),
            });
            SummaryResult {
                system: configuration.system.clone(),
                t: configuration.t,
                status: configuration.status,
                requested_repetitions: configuration.requested_repetitions,
                completed_repetitions: rows.len(),
                medians,
                per_entry,
            }
        })
        .collect()
}

fn per_proof_medians(rows: &[&RawResult]) -> Vec<PerProofMedian> {
    let proof_count = rows
        .iter()
        .map(|result| result.per_proof_setup_seconds.len())
        .min()
        .unwrap_or(0);
    (0..proof_count)
        .map(|proof_index| PerProofMedian {
            proof_index,
            setup_seconds: median_f64(
                rows.iter()
                    .map(|result| result.per_proof_setup_seconds[proof_index])
                    .collect(),
            ),
            proving_seconds: median_f64(
                rows.iter()
                    .map(|result| result.per_proof_proving_seconds[proof_index])
                    .collect(),
            ),
            verification_seconds: median_f64(
                rows.iter()
                    .map(|result| result.per_proof_verification_seconds[proof_index])
                    .collect(),
            ),
            bincode_proof_bytes: median_usize(
                rows.iter()
                    .map(|result| result.per_proof_bincode_bytes[proof_index])
                    .collect(),
            ),
        })
        .collect()
}

fn median_f64(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[middle])
    } else {
        Some((values[middle - 1] + values[middle]) / 2.0)
    }
}

fn median_usize(values: Vec<usize>) -> Option<f64> {
    median_f64(values.into_iter().map(|value| value as f64).collect())
}

fn median_u64(values: Vec<u64>) -> Option<f64> {
    median_f64(values.into_iter().map(|value| value as f64).collect())
}

fn write_reports(output_dir: &Path, report: &ResultsReport) -> AppResult<()> {
    fs::create_dir_all(output_dir)?;
    let json = serde_json::to_vec_pretty(report)?;
    let markdown = render_markdown(report);
    write_atomic(&output_dir.join("results.json"), &json)?;
    write_atomic(&output_dir.join("results.md"), markdown.as_bytes())
}

fn write_atomic(path: &Path, contents: &[u8]) -> AppResult<()> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("report");
    let temporary = path.with_extension(format!("{extension}.tmp-{}", process::id()));
    fs::write(&temporary, contents)?;
    fs::rename(&temporary, path)?;
    Ok(())
}

fn render_markdown(report: &ResultsReport) -> String {
    let mut markdown = String::new();
    markdown.push_str("# SAR-ZK benchmark results\n\n");
    markdown.push_str("This report contains only measured worker values. A configuration labeled `skipped_by_measured_extrapolation` is a budget decision, not a measurement.\n\n");
    markdown.push_str("## Run metadata\n\n");
    markdown.push_str("| Field | Value |\n| --- | --- |\n");
    markdown.push_str(&format!(
        "| Started (UTC) | {} |\n",
        markdown_cell(&report.run_started_at_utc)
    ));
    markdown.push_str(&format!(
        "| Generated (UTC) | {} |\n",
        markdown_cell(&report.generated_at_utc)
    ));
    markdown.push_str(&format!(
        "| Target | {} |\n",
        markdown_cell(&report.metadata.target_triple)
    ));
    markdown.push_str(&format!(
        "| Build profile | {} |\n",
        markdown_cell(&report.metadata.build_profile)
    ));
    markdown.push_str(&format!(
        "| Architecture | {} |\n",
        markdown_cell(&report.metadata.architecture)
    ));
    markdown.push_str(&format!(
        "| Operating system | {} |\n",
        markdown_cell(&report.metadata.operating_system)
    ));
    markdown.push_str(&format!(
        "| CPU | {} ({}) |\n",
        observed_value(&report.metadata.cpu),
        markdown_cell(&report.metadata.cpu.source)
    ));
    markdown.push_str(&format!(
        "| Total cores | {} ({}) |\n",
        observed_value(&report.metadata.total_cores),
        markdown_cell(&report.metadata.total_cores.source)
    ));
    markdown.push_str(&format!(
        "| Memory | {} ({}) |\n",
        observed_value(&report.metadata.memory),
        markdown_cell(&report.metadata.memory.source)
    ));
    markdown.push_str(&format!(
        "| rustc | {} |\n",
        markdown_cell(&report.metadata.rustc)
    ));
    markdown.push_str(&format!(
        "| Rayon threads | {} |\n",
        report.metadata.rayon_threads
    ));
    markdown.push_str(&format!(
        "| RAYON_NUM_THREADS | {} |\n",
        report
            .metadata
            .rayon_num_threads_environment
            .as_deref()
            .map(markdown_cell)
            .unwrap_or_else(|| "unset".to_owned())
    ));
    markdown.push_str(&format!(
        "| Proof-size encoding | {} |\n",
        markdown_cell(&report.metadata.proof_size_encoding)
    ));
    markdown.push_str(&format!(
        "| Peak RSS unit | {} |\n",
        markdown_cell(&report.metadata.peak_rss_unit)
    ));
    markdown.push_str(&format!(
        "| Source revision | {} |\n\n",
        markdown_cell(&report.metadata.source_revision)
    ));

    markdown.push_str("## Exact crate versions\n\n");
    markdown.push_str("| Crate | Version |\n| --- | --- |\n");
    for (crate_name, version) in &report.metadata.crate_versions {
        markdown.push_str(&format!(
            "| {} | {} |\n",
            markdown_cell(crate_name),
            markdown_cell(version)
        ));
    }
    markdown.push('\n');

    markdown.push_str("## Methodology and limits\n\n");
    markdown.push_str("- Each metric is the median of its own repetition-level measurements. Medians of component times need not sum to the median total. The JSON `folds` field is the fixture's Nova comparison bucket; direct systems do not fold.\n");
    markdown.push_str(&format!(
        "- Deterministic fixture seed: `{}`. {}\n",
        report.methodology.fixture_seed, report.methodology.fixture_seed_scope
    ));
    markdown.push_str(&format!("- {}\n", report.methodology.process_isolation));
    markdown.push_str(&format!(
        "- {}\n",
        report.methodology.per_entry_baseline_methodology
    ));
    markdown.push_str(&format!(
        "- {}\n",
        report.methodology.candidate_set_reporting
    ));
    markdown.push_str(&format!("- {}\n", report.methodology.extrapolation_policy));
    for limitation in &report.methodology.baseline_limitations {
        markdown.push_str(&format!("- {limitation}\n"));
    }
    markdown.push_str("- No git revision is collected. Per-worker stdout and stderr are retained under `raw/` and named by system, T, and repetition.\n\n");
    if report
        .raw_results
        .iter()
        .any(|result| result.candidate_set_size <= 16)
    {
        markdown.push_str("**Candidate-set warning:** the reported 16-or-fewer figure is a weak structural count of synthetic receipts sharing issuer, policy, and public bucket. The deterministic published fixture seed exposes witnesses, so it is not an anonymity or privacy demonstration; log leaves are not an anonymity-set claim.\n\n");
    }

    markdown.push_str("## Configuration status\n\n");
    markdown.push_str("| System | T | Completed/requested reps | Status | Elapsed seconds | Evidence |\n| --- | ---: | ---: | --- | ---: | --- |\n");
    for configuration in &report.configurations {
        let evidence = configuration
            .worker_artifacts
            .iter()
            .map(|artifact| {
                format!(
                    "rep {}: {}, {}",
                    artifact.repetition, artifact.stdout_path, artifact.stderr_path
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        markdown.push_str(&format!(
            "| {} | {} | {}/{} | {} | {} | {} |\n",
            configuration.system,
            configuration.t,
            configuration.completed_repetitions,
            configuration.requested_repetitions,
            status_name(configuration.status),
            format_seconds(configuration.elapsed_seconds),
            markdown_cell(if evidence.is_empty() {
                "—"
            } else {
                &evidence
            }),
        ));
        if let Some(estimate) = &configuration.estimate {
            markdown.push_str(&format!(
                "\nMeasured extrapolation for `{}` T={}: {:.6} median observed wall seconds/rep at source T={}; estimated target total for {} reps is {:.6} seconds. {} This is not a benchmark result.\n\n",
                estimate.source_system,
                estimate.target_t,
                estimate.source_median_wall_seconds_per_repetition,
                estimate.source_t,
                estimate.target_repetitions,
                estimate.estimated_total_seconds,
                estimate.method,
            ));
        }
        if let Some(error) = &configuration.error {
            markdown.push_str(&format!("\nRecorded error: {}\n\n", markdown_cell(error)));
        }
    }
    markdown.push('\n');

    append_metric_table(
        &mut markdown,
        "Setup time (seconds)",
        &report.summaries,
        format_seconds_option,
        |metric| metric.setup_seconds,
    );
    append_metric_table(
        &mut markdown,
        "Recursive proving time (seconds)",
        &report.summaries,
        format_seconds_option,
        |metric| metric.recursive_proving_seconds,
    );
    append_metric_table(
        &mut markdown,
        "Compression time (seconds)",
        &report.summaries,
        format_seconds_option,
        |metric| metric.compression_seconds,
    );
    append_metric_table(
        &mut markdown,
        "Total proving time (seconds)",
        &report.summaries,
        format_seconds_option,
        |metric| metric.total_proving_seconds,
    );
    append_metric_table(
        &mut markdown,
        "Verification time (seconds)",
        &report.summaries,
        format_seconds_option,
        |metric| metric.verification_seconds,
    );
    append_metric_table(
        &mut markdown,
        "Bincode proof bytes",
        &report.summaries,
        format_count_option,
        |metric| metric.bincode_proof_bytes,
    );
    append_metric_table(
        &mut markdown,
        "Peak RSS (bytes)",
        &report.summaries,
        format_count_option,
        |metric| metric.peak_rss_bytes,
    );
    append_metric_table(
        &mut markdown,
        "Worker wall time (seconds)",
        &report.summaries,
        format_seconds_option,
        |metric| metric.wall_seconds,
    );
    append_metric_table(
        &mut markdown,
        "Proof count",
        &report.summaries,
        format_count_option,
        |metric| metric.proof_count,
    );
    append_metric_table(
        &mut markdown,
        "Uniform application constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.uniform_application_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Primary constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.primary_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Secondary constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.secondary_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Monolithic application constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.monolithic_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Standalone START branch constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.standalone_start_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Standalone STEP branch constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.standalone_step_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Standalone FINAL branch constraints",
        &report.summaries,
        format_count_option,
        |metric| metric.standalone_final_constraints,
    );
    append_metric_table(
        &mut markdown,
        "Nova comparison bucket (direct systems do not fold)",
        &report.summaries,
        format_count_option,
        |metric| metric.folds,
    );
    append_metric_table(
        &mut markdown,
        "Log leaves",
        &report.summaries,
        format_count_option,
        |metric| metric.log_leaves,
    );
    append_metric_table(
        &mut markdown,
        "Structural synthetic candidate count",
        &report.summaries,
        format_count_option,
        |metric| metric.candidate_set_size,
    );

    append_per_entry_total_table(
        &mut markdown,
        "Per-entry total setup time (seconds)",
        &report.summaries,
        |per_entry| per_entry.total_setup_seconds,
        format_seconds_option,
    );
    append_per_entry_total_table(
        &mut markdown,
        "Per-entry total proving time (seconds)",
        &report.summaries,
        |per_entry| per_entry.total_proving_seconds,
        format_seconds_option,
    );
    append_per_entry_total_table(
        &mut markdown,
        "Per-entry total verification time (seconds)",
        &report.summaries,
        |per_entry| per_entry.total_verification_seconds,
        format_seconds_option,
    );
    append_per_entry_total_table(
        &mut markdown,
        "Per-entry total bincode proof bytes",
        &report.summaries,
        |per_entry| per_entry.total_bincode_proof_bytes,
        format_count_option,
    );

    append_per_proof_table(
        &mut markdown,
        "Per-entry per-proof setup time (seconds)",
        &report.summaries,
        |proof| proof.setup_seconds,
        format_seconds_option,
    );
    append_per_proof_table(
        &mut markdown,
        "Per-entry per-proof proving time (seconds)",
        &report.summaries,
        |proof| proof.proving_seconds,
        format_seconds_option,
    );
    append_per_proof_table(
        &mut markdown,
        "Per-entry per-proof verification time (seconds)",
        &report.summaries,
        |proof| proof.verification_seconds,
        format_seconds_option,
    );
    append_per_proof_table(
        &mut markdown,
        "Per-entry per-proof bincode bytes",
        &report.summaries,
        |proof| proof.bincode_proof_bytes,
        format_count_option,
    );

    markdown.push_str("Full raw repetition-level values, all individual per-proof values, and paths to child stdout/stderr artifacts are in `results.json`. Constraint-count semantics: folded primary/secondary are Nova public-parameter augmented counts; direct primary is raw standalone entry-branch count and secondary is not applicable; monolithic is raw whole-application count excluding 18 direct wrapper input/output equalities; standalone branches are raw START/STEP/FINAL counts excluding wrappers; uniform is the common application relation count.\n");
    markdown
}

fn append_metric_table<F>(
    markdown: &mut String,
    title: &str,
    summaries: &[SummaryResult],
    formatter: fn(Option<f64>) -> String,
    selector: F,
) where
    F: Fn(&MetricMedians) -> Option<f64>,
{
    markdown.push_str(&format!("## {title}\n\n"));
    markdown.push_str(
        "| System | T | Completed/requested reps | Median |\n| --- | ---: | ---: | ---: |\n",
    );
    for summary in summaries {
        markdown.push_str(&format!(
            "| {} | {} | {}/{} | {} |\n",
            summary.system,
            summary.t,
            summary.completed_repetitions,
            summary.requested_repetitions,
            formatter(selector(&summary.medians)),
        ));
    }
    markdown.push('\n');
}

fn append_per_entry_total_table<F>(
    markdown: &mut String,
    title: &str,
    summaries: &[SummaryResult],
    selector: F,
    formatter: fn(Option<f64>) -> String,
) where
    F: Fn(&PerEntrySummary) -> Option<f64>,
{
    markdown.push_str(&format!("## {title}\n\n"));
    markdown.push_str("| T | Completed/requested reps | Median |\n| ---: | ---: | ---: |\n");
    for summary in summaries
        .iter()
        .filter(|summary| summary.system == "per-entry")
    {
        let value = summary.per_entry.as_ref().and_then(&selector);
        markdown.push_str(&format!(
            "| {} | {}/{} | {} |\n",
            summary.t,
            summary.completed_repetitions,
            summary.requested_repetitions,
            formatter(value),
        ));
    }
    markdown.push('\n');
}

fn append_per_proof_table<F>(
    markdown: &mut String,
    title: &str,
    summaries: &[SummaryResult],
    selector: F,
    formatter: fn(Option<f64>) -> String,
) where
    F: Fn(&PerProofMedian) -> Option<f64>,
{
    markdown.push_str(&format!("## {title}\n\n"));
    markdown.push_str(
        "| T | Proof index | Completed/requested reps | Median |\n| ---: | ---: | ---: | ---: |\n",
    );
    for summary in summaries
        .iter()
        .filter(|summary| summary.system == "per-entry")
    {
        if let Some(per_entry) = &summary.per_entry {
            for proof in &per_entry.per_proof_medians {
                markdown.push_str(&format!(
                    "| {} | {} | {}/{} | {} |\n",
                    summary.t,
                    proof.proof_index,
                    summary.completed_repetitions,
                    summary.requested_repetitions,
                    formatter(selector(proof)),
                ));
            }
        }
    }
    markdown.push('\n');
}

fn observed_value(field: &ObservedField) -> String {
    field
        .value
        .as_deref()
        .map(markdown_cell)
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn status_name(status: ConfigurationStatus) -> &'static str {
    match status {
        ConfigurationStatus::Measured => "measured",
        ConfigurationStatus::SkippedByMeasuredExtrapolation => "skipped_by_measured_extrapolation",
        ConfigurationStatus::TimedOut => "timed_out",
        ConfigurationStatus::Failed => "failed",
    }
}

fn format_seconds(value: f64) -> String {
    format!("{value:.6}")
}

fn format_seconds_option(value: Option<f64>) -> String {
    value.map(format_seconds).unwrap_or_else(|| "—".to_owned())
}

fn format_count_option(value: Option<f64>) -> String {
    match value {
        None => "—".to_owned(),
        Some(value) if (value - value.round()).abs() < f64::EPSILON => format!("{:.0}", value),
        Some(value) => format!("{value:.1}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_requested_cli_and_worker_flags_in_any_order() {
        let coordinator = parse_invocation(
            ["--t", "10,100,1000", "--reps", "3", "--out", "out"]
                .into_iter()
                .map(str::to_owned),
        )
        .expect("coordinator arguments parse");
        assert!(matches!(
            coordinator,
            Invocation::Coordinator(CoordinatorArgs {
                ts,
                repetitions: 3,
                output_dir,
            }) if ts == vec![10, 100, 1000]
                && output_dir.as_os_str() == std::ffi::OsStr::new("out")
        ));

        let worker = parse_invocation(
            [
                "--t", "1", "--seed", "0x10", "--worker", "--rep", "2", "--system", "folded",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .expect("worker arguments parse regardless of flag order");
        assert!(matches!(
            worker,
            Invocation::Worker(WorkerArgs {
                system,
                t: 1,
                repetition: 2,
                fixture_seed: 16,
            }) if system == "folded"
        ));
        assert!(parse_invocation(
            ["--t", "4294967296", "--reps", "1", "--out", "out"]
                .into_iter()
                .map(str::to_owned),
        )
        .is_err());
    }

    #[test]
    fn median_sorts_and_averages_even_samples() {
        assert_eq!(median_f64(vec![9.0, 1.0, 5.0]), Some(5.0));
        assert_eq!(median_f64(vec![9.0, 1.0, 5.0, 3.0]), Some(4.0));
        assert_eq!(median_f64(Vec::new()), None);
    }

    #[test]
    fn report_json_round_trip_preserves_raw_and_per_proof_values() {
        let raw = RawResult {
            system: "per-entry".to_owned(),
            t: 1,
            repetition: 0,
            fixture_seed: format_seed(FIXTURE_SEED),
            setup_seconds: 1.0,
            recursive_proving_seconds: None,
            compression_seconds: None,
            total_proving_seconds: 2.0,
            verification_seconds: 3.0,
            bincode_proof_bytes: 44,
            peak_rss_bytes: 55,
            wall_seconds: 6.0,
            proof_count: 2,
            per_proof_setup_seconds: vec![1.0, 0.0],
            per_proof_bincode_bytes: vec![20, 24],
            per_proof_proving_seconds: vec![0.8, 1.2],
            per_proof_verification_seconds: vec![1.0, 2.0],
            constraint_counts: ConstraintCounts {
                uniform_application_constraints: 11,
                primary_constraints: 12,
                secondary_constraints: 0,
                monolithic_constraints: None,
                standalone_start_constraints: 13,
                standalone_step_constraints: 14,
                standalone_final_constraints: 15,
            },
            folds: 3,
            log_leaves: 16,
            candidate_set_size: 1,
            candidate_set_assessment: "weak".to_owned(),
            per_entry_totals: Some(PerEntryTotals {
                proof_count: 2,
                setup_seconds: 1.0,
                proving_seconds: 2.0,
                verification_seconds: 3.0,
                bincode_proof_bytes: 44,
            }),
            worker_stdout_path: "raw/per-entry-t1-rep0.stdout.txt".to_owned(),
            worker_stderr_path: "raw/per-entry-t1-rep0.stderr.txt".to_owned(),
        };
        let configuration = ConfigurationResult {
            system: "per-entry".to_owned(),
            t: 1,
            requested_repetitions: 1,
            completed_repetitions: 1,
            status: ConfigurationStatus::Measured,
            elapsed_seconds: 6.0,
            estimate: None,
            error: None,
            worker_artifacts: vec![WorkerArtifacts {
                repetition: 0,
                stdout_path: raw.worker_stdout_path.clone(),
                stderr_path: raw.worker_stderr_path.clone(),
            }],
        };
        let report = ResultsReport {
            schema_version: SCHEMA_VERSION.to_owned(),
            run_started_at_utc: "2026-11-08T00:00:00Z".to_owned(),
            generated_at_utc: "2026-11-08T00:00:01Z".to_owned(),
            metadata: ReportMetadata {
                target_triple: "aarch64-apple-darwin".to_owned(),
                build_profile: "release".to_owned(),
                architecture: "aarch64".to_owned(),
                operating_system: "macos".to_owned(),
                cpu: ObservedField {
                    value: Some("Apple test".to_owned()),
                    source: "test".to_owned(),
                },
                total_cores: ObservedField {
                    value: Some("1".to_owned()),
                    source: "test".to_owned(),
                },
                memory: ObservedField {
                    value: Some("1 GB".to_owned()),
                    source: "test".to_owned(),
                },
                rustc: "rustc test".to_owned(),
                rayon_threads: 1,
                rayon_num_threads_environment: None,
                crate_versions: BTreeMap::from([("zkar-bench".to_owned(), "test".to_owned())]),
                proof_size_encoding: "bincode test".to_owned(),
                peak_rss_unit: "bytes".to_owned(),
                source_revision: "not collected".to_owned(),
            },
            methodology: Methodology {
                fixture_seed: format_seed(FIXTURE_SEED),
                fixture_seed_scope: "test".to_owned(),
                requested_t_values: vec![1],
                requested_repetitions: 1,
                configuration_timeout_seconds: 1,
                process_isolation: "test".to_owned(),
                candidate_set_reporting: "test".to_owned(),
                baseline_limitations: vec!["test".to_owned()],
                per_entry_baseline_methodology: "test".to_owned(),
                extrapolation_policy: "test".to_owned(),
            },
            configurations: vec![configuration],
            raw_results: vec![raw],
            summaries: Vec::new(),
        };
        let encoded = serde_json::to_string(&report).expect("serializes");
        let decoded: ResultsReport = serde_json::from_str(&encoded).expect("deserializes");
        assert_eq!(decoded.raw_results.len(), 1);
        assert_eq!(decoded.raw_results[0].per_proof_bincode_bytes, vec![20, 24]);
        assert_eq!(
            decoded.raw_results[0]
                .per_entry_totals
                .as_ref()
                .expect("per-entry totals present")
                .proof_count,
            2
        );
    }
}
