//! The SAR-ZK policy (spec §6): a tool allowlist, an egress flag and a
//! payment bound. This is the off-circuit mirror of the in-circuit check;
//! the circuit proves conformance, this crate states what conformance is.

use crate::lexical::is_digest;
use crate::statement::Inventory;
use crate::ZkarError;

/// Largest allowlist the depth-16 allowlist tree can hold (spec §6).
pub const MAX_ALLOWLIST: usize = 1 << 16;

/// A policy. Committed as `policy_commitment = H_policy(allowlist_root,
/// egress_allowed, payment_bound)`. Fields are private so every policy goes
/// through `Policy::new` and its checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    allowlist: Vec<String>,
    allow_egress: bool,
    payment_bound: u64,
}

impl Policy {
    /// Build a policy. The allowlist is sorted; duplicates are rejected, so one
    /// policy has exactly one allowlist root. The bound must be below 2^32.
    pub fn new(
        mut allowlist: Vec<String>,
        allow_egress: bool,
        payment_bound: u64,
    ) -> Result<Self, ZkarError> {
        for d in &allowlist {
            if !is_digest(d) {
                return Err(ZkarError::BadLexicalForm {
                    member: "allowlist",
                    value: d.clone(),
                });
            }
        }
        if allowlist.len() > MAX_ALLOWLIST {
            return Err(ZkarError::Other("allowlist is longer than 65,536 entries"));
        }
        allowlist.sort();
        if allowlist.windows(2).any(|w| w[0] == w[1]) {
            return Err(ZkarError::Other("allowlist contains a duplicate digest"));
        }
        if payment_bound >= (1u64 << 32) {
            return Err(ZkarError::Other("payment bound must be below 2^32"));
        }
        Ok(Policy {
            allowlist,
            allow_egress,
            payment_bound,
        })
    }

    pub fn allowlist(&self) -> &[String] {
        &self.allowlist
    }
    pub fn allow_egress(&self) -> bool {
        self.allow_egress
    }
    pub fn payment_bound(&self) -> u64 {
        self.payment_bound
    }

    /// True if `digest` is on the allowlist.
    pub fn allows_tool(&self, digest: &str) -> bool {
        self.allowlist
            .binary_search_by(|d| d.as_str().cmp(digest))
            .is_ok()
    }

    /// Evaluate the predicate on an inventory. Order of checks mirrors the
    /// spec: tools, egress, payments.
    pub fn check(&self, inv: &Inventory) -> Result<(), ZkarError> {
        for d in &inv.tool_artifacts {
            if !self.allows_tool(d) {
                return Err(ZkarError::PolicyViolation(format!(
                    "tool artifact {d} not in allowlist"
                )));
            }
        }
        if !inv.egress_artifacts.is_empty() && !self.allow_egress {
            return Err(ZkarError::PolicyViolation(
                "egress occurred and is not allowed".into(),
            ));
        }
        if inv.payment_artifacts.len() as u64 > self.payment_bound {
            return Err(ZkarError::PolicyViolation(format!(
                "payment count {} exceeds bound {}",
                inv.payment_artifacts.len(),
                self.payment_bound
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D0: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn inv(tools: &[&str], egress: &[&str], payments: &[&str]) -> Inventory {
        Inventory {
            tool_artifacts: tools.iter().map(|s| s.to_string()).collect(),
            egress_artifacts: egress.iter().map(|s| s.to_string()).collect(),
            file_artifacts: vec![],
            payment_artifacts: payments.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn happy_path() {
        let p = Policy::new(vec![D0.into()], false, 1).unwrap();
        assert!(p.check(&inv(&[D0], &[], &[D1])).is_ok());
    }

    #[test]
    fn disallowed_tool() {
        let p = Policy::new(vec![D0.into()], false, 1).unwrap();
        assert!(matches!(
            p.check(&inv(&[D1], &[], &[])),
            Err(ZkarError::PolicyViolation(_))
        ));
    }

    #[test]
    fn egress_rejected() {
        let p = Policy::new(vec![D0.into()], false, 1).unwrap();
        assert!(matches!(
            p.check(&inv(&[], &[D0], &[])),
            Err(ZkarError::PolicyViolation(_))
        ));
    }

    #[test]
    fn egress_allowed() {
        let p = Policy::new(vec![D0.into()], true, 1).unwrap();
        assert!(p.check(&inv(&[], &[D0], &[])).is_ok());
    }

    #[test]
    fn payment_bound() {
        let p = Policy::new(vec![], false, 0).unwrap();
        assert!(matches!(
            p.check(&inv(&[], &[], &[D1])),
            Err(ZkarError::PolicyViolation(_))
        ));
        let p2 = Policy::new(vec![], false, 1).unwrap();
        assert!(p2.check(&inv(&[], &[], &[D1])).is_ok());
    }

    #[test]
    fn duplicate_allowlist_and_large_bound_rejected() {
        assert!(Policy::new(vec![D0.into(), D0.into()], false, 0).is_err());
        assert!(Policy::new(vec![], false, 1u64 << 32).is_err());
        let p = Policy::new(vec![D1.into(), D0.into()], false, 0).unwrap();
        assert_eq!(p.allowlist(), &[D0.to_string(), D1.to_string()]);
    }

    #[test]
    fn bad_allowlist_digest() {
        assert!(Policy::new(vec!["notadigest".into()], false, 0).is_err());
    }
}
