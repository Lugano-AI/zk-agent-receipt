//! zkar-core — data model and lexical validation for Sealed Agent Receipts
//! (SAR-ZK v0.4-draft). Extends Lugano's Signed Agent Receipt v0.2 with a
//! zero-knowledge proof layer. See spec/SAR-ZK.md.
//!
//! This crate is deliberately dependency-light: it defines the *statement
//! surface* that the circuit (zkar-circuit) commits to. No proof-system code
//! lives here.

pub mod lexical;
pub mod policy;
pub mod statement;
pub mod verify;

pub const PROFILE_A: &str = "sar-zk-v0.4a"; // Ed25519 verified in-circuit
pub const PROFILE_B: &str = "sar-zk-v0.4b"; // Schnorr over Pallas (first target)

/// The log head's hash suite (spec §7.1). Signed inside the head bytes.
pub const HASH_SUITE: &str = "poseidon-pallas-p128pow5t3";

/// Errors that can arise while validating a sealed receipt or its inputs.
#[derive(Debug, PartialEq, Eq)]
pub enum ZkarError {
    /// JSON did not parse, or contained a non-object where an object was required.
    MalformedJson(String),
    /// An object had members outside the fixed schema.
    UnknownMember {
        container: &'static str,
        member: String,
    },
    /// A required member was missing.
    MissingMember {
        container: &'static str,
        member: &'static str,
    },
    /// A value was not a string (v0.2 forbids JSON number tokens).
    NotAString {
        container: &'static str,
        member: &'static str,
    },
    /// A string failed its lexical form (v0.2 §3.1).
    BadLexicalForm { member: &'static str, value: String },
    /// Duplicate object member name after JSON escape decoding (v0.2 §3).
    DuplicateMember {
        container: &'static str,
        member: String,
    },
    /// Wrong array length where a fixed length is required.
    BadLength {
        member: &'static str,
        got: usize,
        want: usize,
    },
    /// Policy predicate failed on the inventory.
    PolicyViolation(String),
    /// Anything else, with a human-readable reason.
    Other(&'static str),
}

impl std::fmt::Display for ZkarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZkarError::MalformedJson(e) => write!(f, "malformed JSON: {e}"),
            ZkarError::UnknownMember { container, member } => {
                write!(f, "unknown member `{member}` in {container}")
            }
            ZkarError::MissingMember { container, member } => {
                write!(f, "missing member `{member}` in {container}")
            }
            ZkarError::NotAString { container, member } => {
                write!(
                    f,
                    "member `{member}` of {container} is not a string (numbers are prohibited)"
                )
            }
            ZkarError::BadLexicalForm { member, value } => {
                write!(f, "member `{member}` fails its lexical form: {value:?}")
            }
            ZkarError::DuplicateMember { container, member } => {
                write!(f, "duplicate member `{member}` in {container}")
            }
            ZkarError::BadLength { member, got, want } => {
                write!(f, "member `{member}` has length {got}, want {want}")
            }
            ZkarError::PolicyViolation(msg) => write!(f, "policy violation: {msg}"),
            ZkarError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ZkarError {}
