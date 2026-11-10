# Security

This repository is research code. It is not for production use. It has not had
an independent security review.

## Report a problem

Email contact@lugano.ai. Include the affected code, steps to reproduce the
problem, and its possible impact. Do not open a public issue for a defect that
does not have a fix yet.

## Scope

Reports about the SAR-ZK specification and this repository's implementation are
in scope. This includes wire parsing, Poseidon hashing, circuit constraints,
proof verification, key handling, and replay storage. Please report a problem
in a dependency here if you are unsure where it belongs.

## Known operating limits

Do not build the verifier with `panic = "abort"`. The verifier catches library
panics and rejects malformed proofs. An abort stops the process instead.

The file-based replay check reads the whole replay file on each check. Its cost
grows with the number of stored pairs. A busy verifier needs an indexed store.
