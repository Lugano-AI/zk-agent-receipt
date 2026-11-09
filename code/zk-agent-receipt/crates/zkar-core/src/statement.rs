//! The inventory surface that SAR-ZK commits to (as a transcript, spec §5),
//! plus the sealed-receipt data model. Parsed by hand (not via derive) so
//! that every v0.2 §3 rule — duplicate members, no JSON numbers, exact
//! schema, lexical forms — is enforced explicitly and testable.

use crate::lexical::*;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

/// serde_json::Value keeps the LAST duplicate member. This wrapper rejects
/// any duplicate (after escape decoding) at every nesting level.
struct Strict(serde_json::Value);
struct StrictVisitor;
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor)
    }
}
impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_bool<E>(self, b: bool) -> Result<Strict, E> {
        Ok(Strict(b.into()))
    }
    fn visit_i64<E>(self, n: i64) -> Result<Strict, E> {
        Ok(Strict(n.into()))
    }
    fn visit_u64<E>(self, n: u64) -> Result<Strict, E> {
        Ok(Strict(n.into()))
    }
    fn visit_f64<E>(self, n: f64) -> Result<Strict, E> {
        Ok(Strict(n.into()))
    }
    fn visit_str<E>(self, s: &str) -> Result<Strict, E> {
        Ok(Strict(s.into()))
    }
    fn visit_string<E>(self, s: String) -> Result<Strict, E> {
        Ok(Strict(s.into()))
    }
    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(serde_json::Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
        let mut v = Vec::new();
        while let Some(Strict(x)) = a.next_element()? {
            v.push(x);
        }
        Ok(Strict(serde_json::Value::Array(v)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
        let mut m = serde_json::Map::new();
        while let Some(k) = a.next_key::<String>()? {
            if m.contains_key(&k) {
                return Err(de::Error::custom(format!("duplicate member `{k}`")));
            }
            let Strict(v) = a.next_value()?;
            m.insert(k, v);
        }
        Ok(Strict(serde_json::Value::Object(m)))
    }
}

/// Parse JSON, rejecting duplicate members (v0.2 §3) anywhere in the tree.
pub fn parse_json_strict(json: &str) -> Result<serde_json::Value, ZkarError> {
    serde_json::from_str::<Strict>(json)
        .map(|s| s.0)
        .map_err(|e| {
            let msg = e.to_string();
            match msg
                .strip_prefix("duplicate member `")
                .and_then(|r| r.split('`').next())
            {
                Some(name) => ZkarError::DuplicateMember {
                    container: "JSON",
                    member: name.to_owned(),
                },
                None => ZkarError::MalformedJson(msg),
            }
        })
}
use crate::{ZkarError, PROFILE_A, PROFILE_B};

/// The inventory portion of a v0.2 statement. Digests are opaque strings in
/// their v0.2 lexical form; the circuit commits to them via Poseidon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub tool_artifacts: Vec<String>,
    pub egress_artifacts: Vec<String>,
    pub file_artifacts: Vec<String>,
    pub payment_artifacts: Vec<String>,
}

/// Public input of a sealed receipt (SAR-ZK §10). The `log_head_signature`
/// is the Ed25519 signature over the head bytes (§7.1), carried in the
/// receipt so the verifier can authenticate the root.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PublicInput {
    pub profile: String, // PROFILE_A (Ed25519 in-circuit) or PROFILE_B (Schnorr over Pallas)
    pub issuer_key_commitment: String, // decimal string encoding a Pallas field element
    pub log_root: String, // decimal string (Pallas field element)
    pub tree_size: String, // DECIMAL, 1..=2147483647
    pub log_id: String,  // ID
    pub log_head_signature: String, // B64URL, Ed25519 over canonical head bytes
    pub policy_commitment: String, // decimal string (Pallas field element)
    pub nullifier_scope: String, // decimal string (Pallas field element), chosen by the verifier
    pub nullifier: String, // decimal string (Pallas field element)
}

/// The current Nova uniform-R1CS wire identifier.
pub const ARITHMETIZATION_NOVA_UNIFORM: &str = "r1cs-nova-uniform";
/// A recognized reserved identifier. Receipt verifiers that implement only
/// uniform Nova must reject it rather than treating it as the current proof
/// system.
pub const ARITHMETIZATION_SUPERNOVA_RESERVED: &str = "r1cs-supernova";
pub const CURVE_PASTA: &str = "pasta";
pub const PROOF_ENCODING_NOVA_BINCODE_LEGACY: &str = "nova-snark-0.76.0/bincode-2.0.1-legacy";
pub const MAX_FOLD_COUNT: u32 = 1 << 20;

/// Naming of the proof stack (SAR-ZK §10). Fixed values, validated on parse.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Algorithm {
    pub arithmetization: String,
    pub curve: String,
    pub proof_encoding: String,
    /// SHA-256 digest of the verifier key, encoded as 64 lowercase hex
    /// characters.
    pub vk_digest: String,
}

/// A sealed receipt (SAR-ZK §10):
/// `{ profile, public_input, proof, fold_count, algorithm }`.
/// The top-level `profile` MUST equal `public_input.profile`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SealedReceipt {
    pub profile: String,
    pub public_input: PublicInput,
    pub proof: String, // B64URL, opaque bytes of the compressed folding proof
    /// Canonical decimal power-of-two padding bucket in `4..=2^20`.
    pub fold_count: String,
    pub algorithm: Algorithm,
}

impl PublicInput {
    pub fn parse(json: &str) -> Result<Self, ZkarError> {
        let v = parse_json_strict(json)?;
        let obj = v
            .as_object()
            .ok_or(ZkarError::Other("public input is not an object"))?;
        let expect = [
            "profile",
            "issuer_key_commitment",
            "log_root",
            "tree_size",
            "log_id",
            "log_head_signature",
            "policy_commitment",
            "nullifier_scope",
            "nullifier",
        ];
        for k in obj.keys() {
            if !expect.contains(&k.as_str()) {
                return Err(ZkarError::UnknownMember {
                    container: "PublicInput",
                    member: k.clone(),
                });
            }
        }
        for k in expect {
            if !obj.contains_key(k) {
                return Err(ZkarError::MissingMember {
                    container: "PublicInput",
                    member: k,
                });
            }
        }
        let get = |k: &'static str| -> Result<String, ZkarError> {
            let val = &obj[k];
            val.as_str()
                .map(str::to_owned)
                .ok_or(ZkarError::NotAString {
                    container: "PublicInput",
                    member: k,
                })
        };
        let pi = PublicInput {
            profile: get("profile")?,
            issuer_key_commitment: get("issuer_key_commitment")?,
            log_root: get("log_root")?,
            tree_size: get("tree_size")?,
            log_id: get("log_id")?,
            log_head_signature: get("log_head_signature")?,
            policy_commitment: get("policy_commitment")?,
            nullifier_scope: get("nullifier_scope")?,
            nullifier: get("nullifier")?,
        };
        pi.validate()?;
        Ok(pi)
    }

    pub fn validate(&self) -> Result<(), ZkarError> {
        if self.profile != PROFILE_A && self.profile != PROFILE_B {
            return Err(ZkarError::BadLexicalForm {
                member: "profile",
                value: self.profile.clone(),
            });
        }
        let fields: [(&'static str, &String); 5] = [
            ("issuer_key_commitment", &self.issuer_key_commitment),
            ("log_root", &self.log_root),
            ("policy_commitment", &self.policy_commitment),
            ("nullifier_scope", &self.nullifier_scope),
            ("nullifier", &self.nullifier),
        ];
        for (member, value) in fields {
            if !is_pallas_field_decimal(value) {
                return Err(ZkarError::BadLexicalForm {
                    member,
                    value: value.clone(),
                });
            }
        }
        for (member, value) in [("tree_size", &self.tree_size)] {
            if !is_decimal(value) {
                return Err(ZkarError::BadLexicalForm {
                    member,
                    value: value.clone(),
                });
            }
        }
        let ts: u64 = self
            .tree_size
            .parse()
            .map_err(|_| ZkarError::BadLexicalForm {
                member: "tree_size",
                value: self.tree_size.clone(),
            })?;
        if !(1..=2147483647).contains(&ts) {
            return Err(ZkarError::BadLexicalForm {
                member: "tree_size",
                value: self.tree_size.clone(),
            });
        }
        if !is_id(&self.log_id) {
            return Err(ZkarError::BadLexicalForm {
                member: "log_id",
                value: self.log_id.clone(),
            });
        }
        // 64 bytes encode to exactly 86 unpadded base64url characters.
        if self.log_head_signature.len() != 86 || !is_b64url(&self.log_head_signature) {
            return Err(ZkarError::BadLexicalForm {
                member: "log_head_signature",
                value: self.log_head_signature.clone(),
            });
        }
        Ok(())
    }
}

impl SealedReceipt {
    pub fn parse(json: &str) -> Result<Self, ZkarError> {
        let v = parse_json_strict(json)?;
        let obj = v
            .as_object()
            .ok_or(ZkarError::Other("sealed receipt is not an object"))?;
        for k in obj.keys() {
            if ![
                "profile",
                "public_input",
                "proof",
                "fold_count",
                "algorithm",
            ]
            .contains(&k.as_str())
            {
                return Err(ZkarError::UnknownMember {
                    container: "SealedReceipt",
                    member: k.clone(),
                });
            }
        }
        for member in [
            "profile",
            "public_input",
            "proof",
            "fold_count",
            "algorithm",
        ] {
            if !obj.contains_key(member) {
                return Err(ZkarError::MissingMember {
                    container: "SealedReceipt",
                    member,
                });
            }
        }
        let profile = obj["profile"].as_str().ok_or(ZkarError::NotAString {
            container: "SealedReceipt",
            member: "profile",
        })?;
        let pi_json = serde_json::to_string(&obj["public_input"])
            .map_err(|e| ZkarError::MalformedJson(e.to_string()))?;
        let public_input = PublicInput::parse(&pi_json)?;
        let proof = obj["proof"].as_str().ok_or(ZkarError::NotAString {
            container: "SealedReceipt",
            member: "proof",
        })?;
        let fold_count = obj["fold_count"].as_str().ok_or(ZkarError::NotAString {
            container: "SealedReceipt",
            member: "fold_count",
        })?;
        let algorithm = parse_algorithm(&obj["algorithm"])?;
        let receipt = SealedReceipt {
            profile: profile.to_owned(),
            public_input,
            proof: proof.to_owned(),
            fold_count: fold_count.to_owned(),
            algorithm,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Recheck every wire invariant, including nested values, for receipts
    /// constructed by Rust callers rather than parsed from JSON.
    pub fn validate(&self) -> Result<(), ZkarError> {
        if self.profile != PROFILE_A && self.profile != PROFILE_B {
            return Err(ZkarError::BadLexicalForm {
                member: "profile",
                value: self.profile.clone(),
            });
        }
        self.public_input.validate()?;
        if self.public_input.profile != self.profile {
            return Err(ZkarError::Other(
                "top-level profile differs from public_input.profile",
            ));
        }
        if !is_b64url(&self.proof) {
            return Err(ZkarError::BadLexicalForm {
                member: "proof",
                value: self.proof.clone(),
            });
        }
        validate_fold_count(&self.fold_count)?;
        self.algorithm.validate()
    }
}

fn parse_algorithm(v: &serde_json::Value) -> Result<Algorithm, ZkarError> {
    let obj = v
        .as_object()
        .ok_or(ZkarError::Other("algorithm is not an object"))?;
    for k in obj.keys() {
        if !["arithmetization", "curve", "proof_encoding", "vk_digest"].contains(&k.as_str()) {
            return Err(ZkarError::UnknownMember {
                container: "Algorithm",
                member: k.clone(),
            });
        }
    }
    for member in ["arithmetization", "curve", "proof_encoding", "vk_digest"] {
        if !obj.contains_key(member) {
            return Err(ZkarError::MissingMember {
                container: "Algorithm",
                member,
            });
        }
    }
    let get = |member: &'static str| -> Result<String, ZkarError> {
        obj[member]
            .as_str()
            .map(str::to_owned)
            .ok_or(ZkarError::NotAString {
                container: "Algorithm",
                member,
            })
    };
    let algorithm = Algorithm {
        arithmetization: get("arithmetization")?,
        curve: get("curve")?,
        proof_encoding: get("proof_encoding")?,
        vk_digest: get("vk_digest")?,
    };
    algorithm.validate()?;
    Ok(algorithm)
}

impl Algorithm {
    /// Validate the exact algorithm identifiers and verifier-key digest form.
    /// `r1cs-supernova` remains parseable solely as a reserved wire value;
    /// an implementation that verifies receipts must explicitly reject it.
    pub fn validate(&self) -> Result<(), ZkarError> {
        if self.arithmetization != ARITHMETIZATION_NOVA_UNIFORM
            && self.arithmetization != ARITHMETIZATION_SUPERNOVA_RESERVED
        {
            return Err(ZkarError::BadLexicalForm {
                member: "arithmetization",
                value: self.arithmetization.clone(),
            });
        }
        if self.curve != CURVE_PASTA {
            return Err(ZkarError::BadLexicalForm {
                member: "curve",
                value: self.curve.clone(),
            });
        }
        if self.proof_encoding != PROOF_ENCODING_NOVA_BINCODE_LEGACY {
            return Err(ZkarError::BadLexicalForm {
                member: "proof_encoding",
                value: self.proof_encoding.clone(),
            });
        }
        if !is_lower_hex_64(&self.vk_digest) {
            return Err(ZkarError::BadLexicalForm {
                member: "vk_digest",
                value: self.vk_digest.clone(),
            });
        }
        Ok(())
    }
}

fn validate_fold_count(fold_count: &str) -> Result<(), ZkarError> {
    let valid = is_decimal(fold_count)
        && fold_count
            .parse::<u32>()
            .ok()
            .is_some_and(|count| (4..=MAX_FOLD_COUNT).contains(&count) && count.is_power_of_two());
    if valid {
        Ok(())
    } else {
        Err(ZkarError::BadLexicalForm {
            member: "fold_count",
            value: fold_count.to_owned(),
        })
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 64
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

impl Inventory {
    /// Total number of artifact digests across all four arrays.
    pub fn total_len(&self) -> usize {
        self.tool_artifacts.len()
            + self.egress_artifacts.len()
            + self.file_artifacts.len()
            + self.payment_artifacts.len()
    }
}

/// Parse the inventory arrays out of a v0.2 statement JSON object.
/// Enforces: arrays of DIGEST strings, no unknown members, no JSON numbers.
pub fn parse_inventory(json: &str) -> Result<Inventory, ZkarError> {
    let v = parse_json_strict(json)?;
    let obj = v
        .as_object()
        .ok_or(ZkarError::Other("inventory is not an object"))?;
    for k in obj.keys() {
        if ![
            "tool_artifacts",
            "egress_artifacts",
            "file_artifacts",
            "payment_artifacts",
        ]
        .contains(&k.as_str())
        {
            return Err(ZkarError::UnknownMember {
                container: "Inventory",
                member: k.clone(),
            });
        }
    }
    let mut inv = Inventory {
        tool_artifacts: vec![],
        egress_artifacts: vec![],
        file_artifacts: vec![],
        payment_artifacts: vec![],
    };
    let slots: [(&'static str, &mut Vec<String>); 4] = [
        ("tool_artifacts", &mut inv.tool_artifacts),
        ("egress_artifacts", &mut inv.egress_artifacts),
        ("file_artifacts", &mut inv.file_artifacts),
        ("payment_artifacts", &mut inv.payment_artifacts),
    ];
    for (member, slot) in slots {
        let arr = match obj.get(member) {
            Some(serde_json::Value::Array(a)) => a,
            Some(_) => return Err(ZkarError::Other("inventory member is not an array")),
            None => {
                return Err(ZkarError::MissingMember {
                    container: "Inventory",
                    member,
                })
            }
        };
        for item in arr {
            let d = item.as_str().ok_or(ZkarError::NotAString {
                container: "Inventory",
                member,
            })?;
            if !is_digest(d) {
                return Err(ZkarError::BadLexicalForm {
                    member,
                    value: d.to_owned(),
                });
            }
            slot.push(d.to_owned());
        }
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pi_json() -> String {
        r#"{
            "profile": "sar-zk-v0.4a",
            "issuer_key_commitment": "1",
            "log_root": "42",
            "tree_size": "17",
            "log_id": "log.1",
            "log_head_signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "policy_commitment": "7",
            "nullifier_scope": "5",
            "nullifier": "9"
        }"#
        .to_string()
    }

    #[test]
    fn public_input_roundtrip() {
        let pi = PublicInput::parse(&pi_json()).unwrap();
        assert_eq!(pi.tree_size, "17");
        assert!(pi.validate().is_ok());
    }

    #[test]
    fn rejects_json_numbers() {
        let bad = r#"{ "profile": "sar-zk-v0.4a", "issuer_key_commitment": "1", "log_root": "42",
            "tree_size": 17, "log_id": "log.1", "log_head_signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "policy_commitment": "7", "nullifier_scope": "5", "nullifier": "9" }"#;
        assert!(matches!(
            PublicInput::parse(bad),
            Err(ZkarError::NotAString {
                member: "tree_size",
                ..
            })
        ));
    }

    #[test]
    fn rejects_unknown_members() {
        let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), "x".into());
        let bad = serde_json::to_string(&v).unwrap();
        assert!(matches!(
            PublicInput::parse(&bad),
            Err(ZkarError::UnknownMember { member, .. }) if member == "extra"
        ));
    }

    #[test]
    fn rejects_unknown_profile() {
        let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
        v["profile"] = "sar-zk-v0.4".into(); // unversioned profile rejected
        assert!(PublicInput::parse(&serde_json::to_string(&v).unwrap()).is_err());
    }

    #[test]
    fn rejects_bad_log_head_signature() {
        let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
        v["log_head_signature"] = "AB".into(); // non-canonical b64url
        assert!(matches!(
            PublicInput::parse(&serde_json::to_string(&v).unwrap()),
            Err(ZkarError::BadLexicalForm { member, .. }) if member == "log_head_signature"
        ));
    }

    #[test]
    fn rejects_wrong_length_log_head_signature() {
        for bad in ["", "AA", "AAAA", &"A".repeat(84), &"A".repeat(88)] {
            let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
            v["log_head_signature"] = bad.into();
            assert!(
                PublicInput::parse(&serde_json::to_string(&v).unwrap()).is_err(),
                "{} chars accepted",
                bad.len()
            );
        }
    }

    #[test]
    fn rejects_out_of_range_tree_size() {
        let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
        v["tree_size"] = "2147483648".into();
        assert!(PublicInput::parse(&serde_json::to_string(&v).unwrap()).is_err());
    }

    #[test]
    fn rejects_duplicate_members_including_escaped_names() {
        let dup = pi_json().replacen(
            "\"tree_size\": \"17\",",
            "\"tree_size\": \"17\", \"tree\\u005fsize\": \"18\",",
            1,
        );
        assert!(matches!(
            PublicInput::parse(&dup),
            Err(ZkarError::DuplicateMember { .. })
        ));
        let sr = format!(
            "{{ \"profile\": \"sar-zk-v0.4a\", \"profile\": \"sar-zk-v0.4a\", \"public_input\": {}, \"proof\": \"AAAA\", \"fold_count\": \"4\", \"algorithm\": {{ \"arithmetization\": \"r1cs-supernova\", \"curve\": \"pasta\", \"proof_encoding\": \"nova-snark-0.76.0/bincode-2.0.1-legacy\", \"vk_digest\": \"0000000000000000000000000000000000000000000000000000000000000000\" }} }}",
            pi_json()
        );
        assert!(matches!(
            SealedReceipt::parse(&sr),
            Err(ZkarError::DuplicateMember { .. })
        ));
    }

    #[test]
    fn field_elements_must_be_below_the_pallas_modulus() {
        let p = crate::lexical::PALLAS_P_DECIMAL;
        let below = "28948022309329048855892746252171976963363056481941560715954676764349967630336";
        for member in [
            "issuer_key_commitment",
            "log_root",
            "policy_commitment",
            "nullifier_scope",
            "nullifier",
        ] {
            let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
            v[member] = p.into();
            assert!(
                PublicInput::parse(&serde_json::to_string(&v).unwrap()).is_err(),
                "{member} = p accepted"
            );
            v[member] = below.into();
            assert!(
                PublicInput::parse(&serde_json::to_string(&v).unwrap()).is_ok(),
                "{member} = p-1 rejected"
            );
        }
    }

    #[test]
    fn nullifier_scope_is_required() {
        let mut v: serde_json::Value = serde_json::from_str(&pi_json()).unwrap();
        v.as_object_mut().unwrap().remove("nullifier_scope");
        assert!(matches!(
            PublicInput::parse(&serde_json::to_string(&v).unwrap()),
            Err(ZkarError::MissingMember {
                member: "nullifier_scope",
                ..
            })
        ));
    }

    #[test]
    fn inventory_parse() {
        let inv = parse_inventory(
            r#"{ "tool_artifacts": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"],
                 "egress_artifacts": [], "file_artifacts": [],
                 "payment_artifacts": ["sha256:1111111111111111111111111111111111111111111111111111111111111111"] }"#,
        )
        .unwrap();
        assert_eq!(inv.tool_artifacts.len(), 1);
        assert_eq!(inv.payment_artifacts.len(), 1);
        assert!(inv.egress_artifacts.is_empty());
    }

    #[test]
    fn sealed_receipt_parse() {
        let sr = format!(
            "{{ \"profile\": \"sar-zk-v0.4a\", \"public_input\": {}, \"proof\": \"AAAA\", \"fold_count\": \"4\", \"algorithm\": {{ \"arithmetization\": \"r1cs-supernova\", \"curve\": \"pasta\", \"proof_encoding\": \"nova-snark-0.76.0/bincode-2.0.1-legacy\", \"vk_digest\": \"0000000000000000000000000000000000000000000000000000000000000000\" }} }}",
            pi_json()
        );
        let parsed = SealedReceipt::parse(&sr).unwrap();
        assert_eq!(parsed.profile, "sar-zk-v0.4a");
        assert_eq!(parsed.algorithm.curve, "pasta");

        let bad_proof = format!(
            "{{ \"profile\": \"sar-zk-v0.4a\", \"public_input\": {}, \"proof\": \"AB\", \"fold_count\": \"4\", \"algorithm\": {{ \"arithmetization\": \"r1cs-supernova\", \"curve\": \"pasta\", \"proof_encoding\": \"nova-snark-0.76.0/bincode-2.0.1-legacy\", \"vk_digest\": \"0000000000000000000000000000000000000000000000000000000000000000\" }} }}",
            pi_json()
        ); // non-canonical b64url
        assert!(matches!(
            SealedReceipt::parse(&bad_proof),
            Err(ZkarError::BadLexicalForm {
                member: "proof",
                ..
            })
        ));

        let mismatch = format!(
            "{{ \"profile\": \"sar-zk-v0.4b\", \"public_input\": {}, \"proof\": \"AAAA\", \"fold_count\": \"4\", \"algorithm\": {{ \"arithmetization\": \"r1cs-supernova\", \"curve\": \"pasta\", \"proof_encoding\": \"nova-snark-0.76.0/bincode-2.0.1-legacy\", \"vk_digest\": \"0000000000000000000000000000000000000000000000000000000000000000\" }} }}",
            pi_json()
        ); // public_input says v0.4a
        assert!(SealedReceipt::parse(&mismatch).is_err());

        let bad_alg = "{\"profile\":\"sar-zk-v0.4a\",\"public_input\":".to_owned()
            + &pi_json()
            + ",\"proof\":\"AAAA\",\"algorithm\":{\"arithmetization\":\"r1cs-supernova\",\"curve\":\"groth16\"}}";
        assert!(SealedReceipt::parse(&bad_alg).is_err());
    }
}
