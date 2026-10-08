# Security policy

## Supported versions

The version declared in `VERSION` on the main branch receives fixes. Older
versions are not patched; refresh the marketplace snapshot and reinstall the
plugin as described in `README.md`.

## Reporting a vulnerability

Use GitHub private vulnerability reporting on this repository (Security tab,
"Report a vulnerability"). Do not open a public issue for a security problem,
and never include AWS account ids, credentials, policy files or command
transcripts in a report. Reports are acknowledged within five business days.

A gate bypass counts as a vulnerability: any shell text that reaches an AWS CLI
mutation, a sensitive read, a credential or endpoint override, or a wrapper the
classifier should have denied. Include the synthetic hook event that reproduces
it; the offline suites under
`plugins/aws-secure-ops/skills/aws-secure-ops/scripts` show the shape.

## What the plugin protects and what it cannot

The hook is a safety belt, not a sandbox. IAM read-only roles, SCPs, permission
boundaries, credential separation and CloudTrail are the enforceable controls.
The gate removes dangerous paths from the agents it supervises, fails closed
when its classifier crashes, and keeps only metadata in the ledger, never raw
command text or secret values. The threat model and the residual risks are
documented in
`plugins/aws-secure-ops/skills/aws-secure-ops/references/threat-model.md` and
in the "Security boundary" section of `README.md`.
