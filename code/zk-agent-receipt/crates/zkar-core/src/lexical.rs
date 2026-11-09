//! Lexical forms, mirroring Signed Agent Receipt v0.2 §3.1 exactly so that
//! circuit commitments bind the same strings the offline checker sees.

/// `ID` — ASCII matching `[a-z][a-z0-9._-]{0,63}`.
pub fn is_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() {
        return false;
    }
    if !b[0].is_ascii_lowercase() {
        return false;
    }
    b.len() <= 64
        && b[1..].iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// `DIGEST` — `sha256:` followed by exactly 64 lowercase hex characters.
pub fn is_digest(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 71
        && b.starts_with(b"sha256:")
        && b[7..]
            .iter()
            .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `DECIMAL` — `0` or `[1-9][0-9]*`; no sign, whitespace, leading zero, point, exponent.
pub fn is_decimal(s: &str) -> bool {
    let b = s.as_bytes();
    match b.len() {
        0 => false,
        1 => b[0].is_ascii_digit(),
        _ => b[0].is_ascii_digit() && b[0] != b'0' && b[1..].iter().all(|c| c.is_ascii_digit()),
    }
}

/// The Pallas base-field modulus p = 2^254 + 45560315531419706090280762371685220353.
pub const PALLAS_P_DECIMAL: &str =
    "28948022309329048855892746252171976963363056481941560715954676764349967630337";

/// `F` — a DECIMAL that is a canonical Pallas base-field element (< p). Never reduced.
pub fn is_pallas_field_decimal(s: &str) -> bool {
    is_decimal(s)
        && (s.len() < PALLAS_P_DECIMAL.len()
            || (s.len() == PALLAS_P_DECIMAL.len() && s < PALLAS_P_DECIMAL))
}

/// `B64URL` — unpadded RFC 4648 base64url, canonical (decode/re-encode compares equal).
pub fn is_b64url(s: &str) -> bool {
    let b = s.as_bytes();
    if b.iter()
        .any(|&c| !(c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_')))
    {
        return false; // forbidden alphabet char (padding included)
    }
    if b.len() % 4 == 1 {
        return false; // impossible length
    }
    // Canonicality: unused bits in the final quantum must be zero.
    match b.len() % 4 {
        2 => {
            // 2 chars = 12 bits carry 1 byte; the low 4 bits must be 0
            b64_val(b[b.len() - 1]).is_some_and(|v| v & 0b1111 == 0)
        }
        3 => {
            // 3 chars = 18 bits carry 2 bytes; the low 2 bits must be 0
            b64_val(b[b.len() - 1]).is_some_and(|v| v & 0b11 == 0)
        }
        _ => true,
    }
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(is_id("a"));
        assert!(is_id("log.1_x-y"));
        assert!(!is_id(""));
        assert!(!is_id("A"));
        assert!(!is_id("1a"));
        assert!(!is_id("a b"));
        assert!(!is_id(&"a".repeat(65)));
    }

    #[test]
    fn digests() {
        assert!(is_digest(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_digest("sha256:0000")); // too short
        assert!(!is_digest(
            "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(!is_digest(
            "sha256:000000000000000000000000000000000000000000000000000000000000000z"
        ));
    }

    #[test]
    fn decimals() {
        for good in ["0", "1", "10", "2147483647"] {
            assert!(is_decimal(good), "{good}");
        }
        for bad in ["", "00", "01", "-1", "1.0", "1e0", " 1", "1 "] {
            assert!(!is_decimal(bad), "{bad}");
        }
    }

    #[test]
    fn b64url_forms() {
        assert!(is_b64url(""));
        assert!(is_b64url("AA")); // 0 bits used — canonical
        assert!(!is_b64url("AE")); // leftover bits 0100 — non-canonical
        assert!(is_b64url("AQ")); // [0x01], leftover bits 0000 — canonical
        assert!(is_b64url("AAE")); // [0x00, 0x01] — canonical
        assert!(is_b64url("AAA"));
        assert!(is_b64url("AAAA"));
        assert!(!is_b64url("AB")); // low 2 bits set — non-canonical
        assert!(!is_b64url("AF")); // low 4 bits set — non-canonical
        assert!(!is_b64url("A")); // length % 4 == 1
        assert!(!is_b64url("AA==")); // padding forbidden
        assert!(!is_b64url("A/B")); // standard alphabet forbidden
    }
}
