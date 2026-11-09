//! Fresh-process benchmark driver for the SAR-ZK baseline guest.
//!
//! Normal `execute` and `prove` runs deliberately reject RISC Zero dev mode.
//! `negative` is the sole exception: it uses a same-process dev-mode positive
//! control, then proves that a malformed fixture makes the guest panic.

use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use risc0_zkvm::{default_prover, ExecutorEnv, ExecutorImpl, InnerReceipt, Prover, ProverOpts};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Execute,
    Prove,
    Negative,
    Verify,
    CheckArithmetic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptMode {
    Composite,
    Succinct,
}

impl ReceiptMode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "composite" => Ok(Self::Composite),
            "succinct" => Ok(Self::Succinct),
            _ => bail!("unsupported receipt kind {value:?}; expected composite or succinct"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Composite => "composite",
            Self::Succinct => "succinct",
        }
    }

    fn opts(self) -> ProverOpts {
        match self {
            // Keep the baseline's composite measurement on the SDK default.
            Self::Composite => ProverOpts::default(),
            Self::Succinct => ProverOpts::succinct(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NegativeCase {
    WrongTool,
    WrongTranscript,
    WrongSignature,
    WrongNullifier,
}

impl NegativeCase {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "wrong-tool" => Ok(Self::WrongTool),
            "wrong-transcript" => Ok(Self::WrongTranscript),
            "wrong-signature" => Ok(Self::WrongSignature),
            "wrong-nullifier" => Ok(Self::WrongNullifier),
            _ => bail!(
                "unsupported negative case {value:?}; expected wrong-tool, wrong-transcript, wrong-signature, or wrong-nullifier"
            ),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::WrongTool => "wrong-tool",
            Self::WrongTranscript => "wrong-transcript",
            Self::WrongSignature => "wrong-signature",
            Self::WrongNullifier => "wrong-nullifier",
        }
    }
}

struct Cli {
    command: Command,
    t: usize,
    seed: [u8; 32],
    receipt_mode: ReceiptMode,
    negative_case: Option<NegativeCase>,
    receipt_out: Option<PathBuf>,
    receipt_path: Option<PathBuf>,
}

impl Cli {
    fn parse() -> Result<Option<Self>> {
        let mut args = env::args().skip(1);
        let Some(command) = args.next() else {
            print_usage();
            return Ok(None);
        };
        if command == "--help" || command == "-h" {
            print_usage();
            return Ok(None);
        }

        let command = match command.as_str() {
            "execute" => Command::Execute,
            "prove" => Command::Prove,
            "negative" => Command::Negative,
            "verify" => Command::Verify,
            "check-arithmetic" => Command::CheckArithmetic,
            _ => bail!("unknown command {command:?}"),
        };

        let mut t = None;
        let mut seed = relation::DEFAULT_FIXTURE_SEED;
        let mut receipt_mode = ReceiptMode::Composite;
        let mut negative_case = None;
        let mut receipt_out = None;
        let mut receipt_path = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--t" => {
                    let value = args.next().context("--t requires a value")?;
                    t = Some(
                        value
                            .parse::<usize>()
                            .context("--t must be a positive integer")?,
                    );
                }
                "--seed" => {
                    let value = args.next().context("--seed requires 32-byte hex")?;
                    seed = parse_seed(&value)?;
                }
                "--receipt-kind" | "--kind" => {
                    let value = args.next().context("--receipt-kind requires a value")?;
                    receipt_mode = ReceiptMode::parse(&value)?;
                }
                "--case" => {
                    let value = args.next().context("--case requires a value")?;
                    negative_case = Some(NegativeCase::parse(&value)?);
                }
                "--receipt-out" => {
                    let value = args.next().context("--receipt-out requires a path")?;
                    receipt_out = Some(PathBuf::from(value));
                }
                "--receipt" => {
                    let value = args.next().context("--receipt requires a path")?;
                    receipt_path = Some(PathBuf::from(value));
                }
                "--help" | "-h" => {
                    print_usage();
                    return Ok(None);
                }
                _ => bail!("unknown argument {arg:?}"),
            }
        }

        let t = match command {
            Command::Verify => {
                ensure!(t.is_none(), "--t is not valid for verify");
                ensure!(negative_case.is_none(), "--case is only valid for negative");
                ensure!(
                    receipt_mode == ReceiptMode::Composite,
                    "--receipt-kind is only valid for prove"
                );
                ensure!(
                    receipt_out.is_none(),
                    "--receipt-out is only valid for prove"
                );
                ensure!(receipt_path.is_some(), "verify requires --receipt <path>");
                0
            }
            Command::CheckArithmetic => {
                ensure!(t.is_none(), "--t is not valid for check-arithmetic");
                ensure!(negative_case.is_none(), "--case is only valid for negative");
                ensure!(
                    receipt_mode == ReceiptMode::Composite,
                    "--receipt-kind is only valid for prove"
                );
                ensure!(
                    receipt_out.is_none(),
                    "--receipt-out is only valid for prove"
                );
                ensure!(receipt_path.is_none(), "--receipt is only valid for verify");
                0
            }
            Command::Negative => {
                let t = t.context("--t is required")?;
                ensure!(t > 0, "--t must be greater than zero");
                ensure!(negative_case.is_some(), "negative requires --case");
                ensure!(
                    receipt_out.is_none(),
                    "--receipt-out is only valid for prove"
                );
                ensure!(receipt_path.is_none(), "--receipt is only valid for verify");
                t
            }
            Command::Execute => {
                let t = t.context("--t is required")?;
                ensure!(t > 0, "--t must be greater than zero");
                ensure!(negative_case.is_none(), "--case is only valid for negative");
                ensure!(
                    receipt_mode == ReceiptMode::Composite,
                    "--receipt-kind is only valid for prove"
                );
                ensure!(
                    receipt_out.is_none(),
                    "--receipt-out is only valid for prove"
                );
                ensure!(receipt_path.is_none(), "--receipt is only valid for verify");
                t
            }
            Command::Prove => {
                let t = t.context("--t is required")?;
                ensure!(t > 0, "--t must be greater than zero");
                ensure!(negative_case.is_none(), "--case is only valid for negative");
                ensure!(receipt_path.is_none(), "--receipt is only valid for verify");
                t
            }
        };
        if command != Command::Prove && receipt_mode != ReceiptMode::Composite {
            bail!("--receipt-kind is only valid for prove");
        }
        Ok(Some(Self {
            command,
            t,
            seed,
            receipt_mode,
            negative_case,
            receipt_out,
            receipt_path,
        }))
    }
}

struct PreparedFixture {
    input: relation::Input,
    expected: relation::Journal,
    fixture_generation_ms: f64,
    native_verify_before_ms: f64,
    fixture_metadata: Value,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("baseline-host error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let Some(cli) = Cli::parse()? else {
        return Ok(());
    };
    let result = match cli.command {
        Command::Execute => run_execute(&cli)?,
        Command::Prove => run_prove(&cli)?,
        Command::Negative => run_negative(&cli)?,
        Command::Verify => run_verify(&cli)?,
        Command::CheckArithmetic => run_check_arithmetic(&cli)?,
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn run_execute(cli: &Cli) -> Result<Value> {
    let runtime = configure_runtime(false)?;
    let prepared = prepare_fixture(cli.t, cli.seed)?;
    let (executor_env, input_serialization_ms) = make_executor_env(&prepared.input)?;

    let execution_start = Instant::now();
    let mut executor = ExecutorImpl::from_elf(executor_env, methods::BASELINE_ELF)
        .context("constructing local zkVM executor")?;
    let session = executor.run().context("executing baseline guest")?;
    let execution_ms = elapsed_ms(execution_start);
    let stats = session.stats();

    let journal = session
        .journal
        .as_ref()
        .context("successful baseline execution did not produce a journal")?;
    assert_journal(journal, &prepared.expected)?;
    let native_after_start = Instant::now();
    let expected_after = native_verify(&prepared.input)?;
    let native_verify_after_ms = elapsed_ms(native_after_start);
    ensure!(
        expected_after == prepared.expected,
        "native relation result changed between pre- and post-execution checks"
    );

    Ok(json!({
        "schema_version": "sar-zk-baseline-run-v1",
        "status": "ok",
        "mode": "execute",
        "t": cli.t,
        "seed_hex": hex_encode(&cli.seed),
        "fixture": prepared.fixture_metadata,
        "image": image_metadata(),
        "runtime": runtime,
        "timing_ms": {
            "fixture_generation": prepared.fixture_generation_ms,
            "native_verify_before": prepared.native_verify_before_ms,
            "input_serialization": input_serialization_ms,
            "execution": execution_ms,
            "native_verify_after": native_verify_after_ms,
        },
        "cycles": stats_json(&stats),
        "assertions": {
            "native_preverify": true,
            "guest_journal_matches_native": true,
            "native_postverify": true,
        },
        "resource": resource_json(),
        "exit_code": format!("{:?}", session.exit_code),
    }))
}

fn run_prove(cli: &Cli) -> Result<Value> {
    let runtime = configure_runtime(false)?;
    let prepared = prepare_fixture(cli.t, cli.seed)?;
    let (executor_env, input_serialization_ms) = make_executor_env(&prepared.input)?;
    let opts = cli.receipt_mode.opts();
    ensure!(
        !opts.dev_mode(),
        "benchmark prove mode must not use dev mode"
    );

    let prover = default_prover();
    ensure!(
        prover.get_name() == "local",
        "expected explicitly selected local prover, got {}",
        prover.get_name()
    );
    let prove_start = Instant::now();
    let prove_info = prover
        .prove_with_opts(executor_env, methods::BASELINE_ELF, &opts)
        .context("proving baseline guest")?;
    let proof_generation_ms = elapsed_ms(prove_start);
    let receipt = prove_info.receipt;

    let actual_receipt_kind = receipt_kind_name(&receipt.inner);
    ensure!(
        actual_receipt_kind == cli.receipt_mode.name(),
        "requested {} receipt but prover returned {actual_receipt_kind}",
        cli.receipt_mode.name(),
    );
    assert_journal(&receipt.journal, &prepared.expected)?;

    let receipt_verify_start = Instant::now();
    receipt
        .verify(methods::BASELINE_ID)
        .context("verifying generated receipt against BASELINE_ID")?;
    let receipt_verify_ms = elapsed_ms(receipt_verify_start);

    let native_after_start = Instant::now();
    let expected_after = native_verify(&prepared.input)?;
    let native_verify_after_ms = elapsed_ms(native_after_start);
    ensure!(
        expected_after == prepared.expected,
        "native relation result changed between pre- and post-proof checks"
    );
    assert_journal(&receipt.journal, &expected_after)?;
    // Receipt serialization and artifact I/O are deliberately outside the
    // proof-generation timer above. The artifact lets a later fresh process
    // independently verify the exact bytes measured here.
    let receipt_bytes =
        bincode::serialize(&receipt).context("serializing receipt with bincode 1.3")?;
    let bincode_receipt_bytes = receipt_bytes.len();
    let receipt_artifact = match cli.receipt_out.as_deref() {
        Some(path) => write_receipt_artifacts(
            path,
            &receipt_bytes,
            &prepared.expected,
            &prepared.fixture_metadata,
            cli,
            actual_receipt_kind,
        )?,
        None => Value::Null,
    };

    Ok(json!({
        "schema_version": "sar-zk-baseline-run-v1",
        "status": "ok",
        "mode": "prove",
        "receipt_kind": cli.receipt_mode.name(),
        "prover_options": if cli.receipt_mode == ReceiptMode::Composite { "ProverOpts::default()" } else { "ProverOpts::succinct()" },
        "t": cli.t,
        "seed_hex": hex_encode(&cli.seed),
        "fixture": prepared.fixture_metadata,
        "image": image_metadata(),
        "runtime": runtime,
        "timing_ms": {
            "fixture_generation": prepared.fixture_generation_ms,
            "native_verify_before": prepared.native_verify_before_ms,
            "input_serialization": input_serialization_ms,
            "proof_generation": proof_generation_ms,
            "receipt_verify": receipt_verify_ms,
            "native_verify_after": native_verify_after_ms,
        },
        "cycles": stats_json(&prove_info.stats),
        "receipt": {
            "actual_kind": actual_receipt_kind,
            "bincode_1_3_bytes": bincode_receipt_bytes,
            "seal_bytes": receipt.seal_size(),
            "journal_bytes": receipt.journal.bytes.len(),
            "artifact": receipt_artifact,
        },
        "assertions": {
            "dev_mode_disabled": true,
            "local_prover": true,
            "native_preverify": true,
            "guest_journal_matches_native": true,
            "receipt_verified": true,
            "native_postverify": true,
        },
        "resource": resource_json(),
    }))
}

fn run_negative(cli: &Cli) -> Result<Value> {
    let negative_case = cli.negative_case.context("negative requires --case")?;
    let runtime = configure_runtime(true)?;
    let prepared = prepare_fixture(cli.t, cli.seed)?;
    let opts = ProverOpts::default();
    ensure!(
        opts.dev_mode(),
        "negative mode must be the only dev-mode path"
    );
    let prover = default_prover();
    ensure!(prover.get_name() == "local", "expected local prover");

    let (control_env, control_input_serialization_ms) = make_executor_env(&prepared.input)?;
    let control_start = Instant::now();
    let control = prover
        .prove_with_opts(control_env, methods::BASELINE_ELF, &opts)
        .context("dev-mode positive control failed")?;
    let positive_control_prove_ms = elapsed_ms(control_start);
    assert_journal(&control.receipt.journal, &prepared.expected)?;
    control
        .receipt
        .verify(methods::BASELINE_ID)
        .context("dev-mode positive-control receipt did not verify in dev mode")?;

    let mut malformed = prepared.input;
    mutate_negative(&mut malformed, negative_case)?;
    let native_rejection = match relation::verify(&malformed) {
        Ok(_) => bail!(
            "negative {} did not make native verification reject",
            negative_case.name()
        ),
        Err(error) => format!("{error:?}"),
    };
    let (malformed_env, malformed_input_serialization_ms) = make_executor_env(&malformed)?;
    let negative_start = Instant::now();
    let guest_error = match prover.prove_with_opts(malformed_env, methods::BASELINE_ELF, &opts) {
        Ok(_) => bail!(
            "negative {} unexpectedly produced a dev-mode proof",
            negative_case.name()
        ),
        Err(error) => error.to_string(),
    };
    let negative_prove_ms = elapsed_ms(negative_start);
    ensure!(
        guest_error.contains("relation failed"),
        "negative {} failed for an unexpected infrastructure reason: {guest_error}",
        negative_case.name()
    );

    Ok(json!({
        "schema_version": "sar-zk-baseline-run-v1",
        "status": "rejected-as-expected",
        "mode": "negative",
        "negative_case": negative_case.name(),
        "t": cli.t,
        "seed_hex": hex_encode(&cli.seed),
        "fixture": prepared.fixture_metadata,
        "image": image_metadata(),
        "runtime": runtime,
        "timing_ms": {
            "fixture_generation": prepared.fixture_generation_ms,
            "native_verify_before": prepared.native_verify_before_ms,
            "positive_control_input_serialization": control_input_serialization_ms,
            "positive_control_prove": positive_control_prove_ms,
            "malformed_input_serialization": malformed_input_serialization_ms,
            "negative_prove": negative_prove_ms,
        },
        "assertions": {
            "dev_mode_allowed_only_for_negative": true,
            "same_process_positive_control_proved": true,
            "native_relation_rejected_mutation": true,
            "guest_panicked_with_relation_failure": true,
        },
        "native_rejection": native_rejection,
        "guest_error": guest_error,
        "resource": resource_json(),
    }))
}

fn run_verify(cli: &Cli) -> Result<Value> {
    let runtime = configure_runtime(false)?;
    let receipt_path = cli
        .receipt_path
        .as_deref()
        .context("verify requires --receipt <path>")?;
    let receipt_bytes = fs::read(receipt_path)
        .with_context(|| format!("reading receipt artifact {}", receipt_path.display()))?;
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&receipt_bytes)
        .context("deserializing receipt artifact as bincode 1.3")?;

    let sidecar_path = receipt_sidecar_path(receipt_path)?;
    let sidecar_bytes = fs::read(&sidecar_path)
        .with_context(|| format!("reading receipt sidecar {}", sidecar_path.display()))?;
    let sidecar: Value =
        serde_json::from_slice(&sidecar_bytes).context("parsing receipt sidecar JSON")?;
    ensure!(
        sidecar.get("schema_version").and_then(Value::as_str) == Some("sar-zk-baseline-receipt-v1"),
        "receipt sidecar has an unsupported schema"
    );
    let sidecar_image_id: [u32; 8] = serde_json::from_value(
        sidecar
            .pointer("/image/id_words_le")
            .cloned()
            .context("receipt sidecar lacks image.id_words_le")?,
    )
    .context("decoding image ID from receipt sidecar")?;
    ensure!(
        sidecar_image_id == methods::BASELINE_ID,
        "receipt sidecar image ID does not match the linked BASELINE_ID"
    );
    let expected: relation::Journal = serde_json::from_value(
        sidecar
            .get("expected_journal")
            .cloned()
            .context("receipt sidecar lacks expected_journal")?,
    )
    .context("decoding expected journal from receipt sidecar")?;
    let sidecar_bincode_bytes = sidecar
        .get("receipt_bincode_1_3_bytes")
        .and_then(Value::as_u64)
        .context("receipt sidecar lacks receipt_bincode_1_3_bytes")?;
    ensure!(
        sidecar_bincode_bytes == receipt_bytes.len() as u64,
        "receipt artifact length does not match its sidecar"
    );

    let receipt_verify_start = Instant::now();
    receipt
        .verify(methods::BASELINE_ID)
        .context("verifying receipt artifact against BASELINE_ID")?;
    let receipt_verify_ms = elapsed_ms(receipt_verify_start);
    assert_journal(&receipt.journal, &expected)?;

    Ok(json!({
        "schema_version": "sar-zk-baseline-run-v1",
        "status": "ok",
        "mode": "verify",
        "receipt_path": receipt_path.display().to_string(),
        "sidecar_path": sidecar_path.display().to_string(),
        "image": image_metadata(),
        "runtime": runtime,
        "timing_ms": { "receipt_verify": receipt_verify_ms },
        "receipt": {
            "actual_kind": receipt_kind_name(&receipt.inner),
            "bincode_1_3_bytes": receipt_bytes.len(),
            "seal_bytes": receipt.seal_size(),
            "journal_bytes": receipt.journal.bytes.len(),
        },
        "assertions": {
            "sidecar_image_id_matches_linked_image": true,
            "receipt_verified": true,
            "guest_journal_matches_sidecar_expected_journal": true,
        },
        "resource": resource_json(),
    }))
}

fn run_check_arithmetic(_cli: &Cli) -> Result<Value> {
    let runtime = configure_runtime(false)?;
    let native_before_start = Instant::now();
    let expected = relation::accelerator_self_test()
        .map_err(|error| anyhow!("running native accelerator self-test: {error:?}"))?;
    let native_verify_before_ms = elapsed_ms(native_before_start);
    let (executor_env, executor_env_build_ms) = make_empty_executor_env()?;

    // This deliberately names only CHECK_ELF. The arithmetic diagnostic has a
    // distinct image and cannot change baseline receipt cycles or journals.
    let execution_start = Instant::now();
    let mut executor = ExecutorImpl::from_elf(executor_env, methods::CHECK_ELF)
        .context("constructing local arithmetic-check zkVM executor")?;
    let session = executor.run().context("executing arithmetic-check guest")?;
    let execution_ms = elapsed_ms(execution_start);
    let stats = session.stats();
    let journal = session
        .journal
        .as_ref()
        .context("successful arithmetic-check execution did not produce a journal")?;
    let guest: relation::AcceleratorSelfTest = journal
        .decode()
        .context("decoding arithmetic-check guest journal")?;
    ensure!(
        guest == expected,
        "arithmetic-check guest result differs from native accelerator self-test"
    );

    let native_after_start = Instant::now();
    let expected_after = relation::accelerator_self_test()
        .map_err(|error| anyhow!("rerunning native accelerator self-test: {error:?}"))?;
    let native_verify_after_ms = elapsed_ms(native_after_start);
    ensure!(
        expected_after == expected,
        "native accelerator self-test changed between pre- and post-execution checks"
    );

    Ok(json!({
        "schema_version": "sar-zk-baseline-run-v1",
        "status": "ok",
        "mode": "check-arithmetic",
        "image": check_image_metadata(),
        "runtime": runtime,
        "timing_ms": {
            "native_self_test_before": native_verify_before_ms,
            "executor_env_build": executor_env_build_ms,
            "execution": execution_ms,
            "native_self_test_after": native_verify_after_ms,
        },
        "cycles": stats_json(&stats),
        "assertions": {
            "check_image_is_separate_from_baseline": true,
            "accelerated_guest_self_test_matches_native": true,
            "native_self_test_stable": true,
        },
        "resource": resource_json(),
        "exit_code": format!("{:?}", session.exit_code),
    }))
}

fn write_receipt_artifacts(
    receipt_path: &Path,
    receipt_bytes: &[u8],
    expected: &relation::Journal,
    fixture_metadata: &Value,
    cli: &Cli,
    actual_receipt_kind: &str,
) -> Result<Value> {
    ensure!(
        receipt_path.file_name().is_some(),
        "--receipt-out must name a receipt file"
    );
    let sidecar_path = receipt_sidecar_path(receipt_path)?;
    let sidecar = json!({
        "schema_version": "sar-zk-baseline-receipt-v1",
        "receipt_bincode_encoding": "bincode 1.3.3",
        "receipt_bincode_1_3_bytes": receipt_bytes.len(),
        "receipt_kind": actual_receipt_kind,
        "image": image_metadata(),
        "expected_journal": expected,
        "t": cli.t,
        "seed_hex": hex_encode(&cli.seed),
        "fixture": fixture_metadata,
    });

    // Both writes occur after every benchmark timing. Atomic replacement avoids
    // treating a truncated artifact as evidence after an interrupted run.
    atomic_write(receipt_path, receipt_bytes)
        .with_context(|| format!("writing receipt artifact {}", receipt_path.display()))?;
    let sidecar_bytes =
        serde_json::to_vec_pretty(&sidecar).context("serializing receipt sidecar")?;
    atomic_write(&sidecar_path, &sidecar_bytes)
        .with_context(|| format!("writing receipt sidecar {}", sidecar_path.display()))?;

    Ok(json!({
        "receipt_path": receipt_path.display().to_string(),
        "sidecar_path": sidecar_path.display().to_string(),
        "written_after_timing": true,
    }))
}

fn receipt_sidecar_path(receipt_path: &Path) -> Result<PathBuf> {
    let mut file_name = receipt_path
        .file_name()
        .context("receipt path has no filename")?
        .to_os_string();
    file_name.push(".json");
    Ok(receipt_path.with_file_name(file_name))
}

fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut temporary_name = path.file_name().unwrap_or_default().to_os_string();
    temporary_name.push(format!(".tmp-{}", std::process::id()));
    let temporary_path = path.with_file_name(temporary_name);
    fs::write(&temporary_path, contents)?;
    fs::rename(temporary_path, path)
}

fn prepare_fixture(t: usize, seed: [u8; 32]) -> Result<PreparedFixture> {
    let fixture_start = Instant::now();
    let input =
        relation::generate(t, seed).map_err(|error| anyhow!("generating fixture: {error:?}"))?;
    let fixture_generation_ms = elapsed_ms(fixture_start);
    let native_start = Instant::now();
    let expected = native_verify(&input)?;
    let native_verify_before_ms = elapsed_ms(native_start);
    let fixture_metadata = serde_json::to_value(input.benchmark_metadata())
        .context("serializing fixture benchmark metadata")?;
    Ok(PreparedFixture {
        input,
        expected,
        fixture_generation_ms,
        native_verify_before_ms,
        fixture_metadata,
    })
}

fn native_verify(input: &relation::Input) -> Result<relation::Journal> {
    relation::verify(input)
        .map_err(|error| anyhow!("native relation verification failed: {error:?}"))
}

fn make_executor_env(input: &relation::Input) -> Result<(ExecutorEnv<'static>, f64)> {
    let start = Instant::now();
    let executor_env = ExecutorEnv::builder()
        .write(input)
        .context("serializing fixture for guest stdin")?
        .build()
        .context("building guest executor environment")?;
    Ok((executor_env, elapsed_ms(start)))
}

fn make_empty_executor_env() -> Result<(ExecutorEnv<'static>, f64)> {
    let start = Instant::now();
    let executor_env = ExecutorEnv::builder()
        .build()
        .context("building empty arithmetic-check executor environment")?;
    Ok((executor_env, elapsed_ms(start)))
}

fn assert_journal(journal: &risc0_zkvm::Journal, expected: &relation::Journal) -> Result<()> {
    let guest: relation::Journal = journal.decode().context("decoding guest journal")?;
    ensure!(
        guest == *expected,
        "guest journal differs from native relation result"
    );
    Ok(())
}

fn mutate_negative(input: &mut relation::Input, negative_case: NegativeCase) -> Result<()> {
    match negative_case {
        NegativeCase::WrongTool => {
            let entry = input
                .entries
                .first_mut()
                .context("fixture has no entry for wrong-tool")?;
            entry.digest_hi[0] ^= 1;
        }
        NegativeCase::WrongTranscript => input.statement.transcript[0] ^= 1,
        NegativeCase::WrongSignature => input.signature.s[0] ^= 1,
        NegativeCase::WrongNullifier => input.expected_nullifier[0] ^= 1,
    }
    Ok(())
}

fn configure_runtime(allow_dev_mode: bool) -> Result<Value> {
    if !allow_dev_mode && env_truthy("RISC0_DEV_MODE") {
        bail!("RISC0_DEV_MODE is enabled; normal benchmark modes require valid proofs");
    }
    force_or_require("RISC0_PROVER", "local")?;
    force_or_require("RISC0_EXECUTOR", "local")?;
    set_env_before_threads("RISC0_DEV_MODE", if allow_dev_mode { "1" } else { "0" });
    Ok(json!({
        "risc0_zkvm_version": risc0_zkvm::VERSION,
        "prover": "local",
        "executor": "local",
        "dev_mode": allow_dev_mode,
        "backend": "cpu",
        "backend_basis": "RISC Zero v3.0.6 source selects CPU segment and recursion HALs when cuda is absent; its Apple-Silicon Metal branches are commented out. This package enables std+prove and does not enable cuda.",
        "risc0_backend_env_supported": false,
        "available_parallelism": std::thread::available_parallelism().ok().map(|count| count.get()),
    }))
}

fn force_or_require(name: &str, expected: &str) -> Result<()> {
    if let Ok(value) = env::var(name) {
        if !value.is_empty() && !value.eq_ignore_ascii_case(expected) {
            bail!("{name}={value:?}; this harness requires {name}={expected:?}");
        }
    }
    set_env_before_threads(name, expected);
    Ok(())
}

fn set_env_before_threads(name: &str, value: &str) {
    // Called before RISC Zero/Rayon constructs worker threads. Environment
    // mutation is unsafe because concurrent C readers would otherwise race.
    unsafe { env::set_var(name, value) };
}

fn env_truthy(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

fn receipt_kind_name(inner: &InnerReceipt) -> &'static str {
    match inner {
        InnerReceipt::Composite(_) => "composite",
        InnerReceipt::Succinct(_) => "succinct",
        InnerReceipt::Groth16(_) => "groth16",
        InnerReceipt::Fake(_) => "fake",
        _ => "unknown",
    }
}

fn stats_json(stats: &risc0_zkvm::SessionStats) -> Value {
    json!({
        "segments": stats.segments,
        "total_cycles": stats.total_cycles,
        "user_cycles": stats.user_cycles,
        "paging_cycles": stats.paging_cycles,
        "reserved_cycles": stats.reserved_cycles,
    })
}

fn image_metadata() -> Value {
    json!({ "id_words_le": methods::BASELINE_ID, "elf_bytes": methods::BASELINE_ELF.len() })
}

fn check_image_metadata() -> Value {
    json!({ "id_words_le": methods::CHECK_ID, "elf_bytes": methods::CHECK_ELF.len() })
}

fn resource_json() -> Value {
    // This is called only after each command's measured operation has ended.
    // In particular, it does not create a Rayon pool before a proof timer.
    json!({
        "peak_rss": peak_rss().map(|(bytes, source)| json!({ "bytes": bytes, "source": source })),
        "rayon_current_num_threads_after_timing": rayon::current_num_threads(),
        "rayon_num_threads_env": env::var("RAYON_NUM_THREADS").ok(),
    })
}

fn peak_rss() -> Option<(u64, &'static str)> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    #[cfg(target_os = "macos")]
    {
        Some((
            usage.ru_maxrss as u64,
            "getrusage(RUSAGE_SELF); macOS bytes",
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some((
            (usage.ru_maxrss as u64).saturating_mul(1024),
            "getrusage(RUSAGE_SELF); converted from KiB",
        ))
    }
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1_000.0
}

fn parse_seed(input: &str) -> Result<[u8; 32]> {
    let input = input.strip_prefix("0x").unwrap_or(input);
    ensure!(
        input.len() == 64,
        "--seed must contain exactly 64 hexadecimal characters"
    );
    let mut seed = [0u8; 32];
    for (index, output) in seed.iter_mut().enumerate() {
        let position = index * 2;
        *output = (hex_nibble(input.as_bytes()[position])? << 4)
            | hex_nibble(input.as_bytes()[position + 1])?;
    }
    Ok(seed)
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("--seed contains non-hexadecimal data"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn print_usage() {
    println!("Usage:\n  baseline-host execute --t <T> [--seed <64-hex>]\n  baseline-host prove --t <T> [--receipt-kind composite|succinct] [--seed <64-hex>] [--receipt-out <path>]\n  baseline-host verify --receipt <path>\n  baseline-host check-arithmetic\n  baseline-host negative --t <T> --case wrong-tool|wrong-transcript|wrong-signature|wrong-nullifier [--seed <64-hex>]\n\nAll successful commands print one JSON object to stdout. `prove --receipt-out` writes bincode 1.3 receipt bytes plus a JSON sidecar; `verify` checks both. `check-arithmetic` uses the separate CHECK image and never executes BASELINE_ELF.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use risc0_zkvm::ReceiptKind;

    // Exercise the actual CLI-to-SDK option mapping without invoking a prover.
    // Run with RISC0_DEV_MODE=0, as required for the later serial benchmark.
    #[test]
    fn receipt_modes_select_real_composite_and_succinct_options() {
        for (name, expected) in [
            ("composite", ReceiptKind::Composite),
            ("succinct", ReceiptKind::Succinct),
        ] {
            let mode = ReceiptMode::parse(name).unwrap();
            let options = mode.opts();
            assert_eq!(options.receipt_kind, expected);
            assert!(!options.dev_mode(), "run this test with RISC0_DEV_MODE=0");
        }
        assert!(ReceiptMode::parse("fake").is_err());
    }
}
