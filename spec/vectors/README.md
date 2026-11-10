# Test vectors

`poseidon.json` covers every Poseidon domain label in SAR-ZK section 3.2.
The top-level object contains `field_modulus` and `domains`.

Each entry in `domains` has a `domain` string and a `vectors` array. Each vector
has a `name`, an ordered `inputs` array, and an `output` string. Compute
`H_domain(inputs)` with the sponge in section 3.2 and compare the field element
with `output`.

All field elements use canonical decimal strings. Values are greater than or
equal to zero and less than `field_modulus`. Input order is significant. An
empty array means zero inputs.

Every domain has six standard cases: `empty`, `zero`, `one`, `p_minus_one`,
`mixed_even`, and `mixed_odd`. A domain also has `profile_arity` when its
profile input length differs from all six standard lengths. The mixed cases
contain fixed values in a fixed order. The empty, even, and odd cases also test
sponge framing at different input lengths.

`receipts/manifest.json` describes the sealed-receipt wire-format cases in
`receipts/`. Each receipt file changes one thing from the valid receipt, except
`valid.json` itself.

The reject cases are a sample, not a full list. They cover one case for each
kind of parser error and each lexical rule. They do not cover every member.

`valid.json` passes the wire-format checks only. Its proof is a placeholder and
does not verify.

The Poseidon outputs come from this repository's implementation. They pin its
behaviour. No independent implementation has confirmed them yet.
