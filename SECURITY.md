# Security policy

This repository intentionally contains honeypot personas, synthetic credentials,
attack signatures, and defensive malware-analysis tooling. Values marked
`DECOY_ONLY` are fictional and must never be reused for real authentication.

Do not report expected honeypot behavior as a vulnerability. Please privately
report issues that could expose the host, bypass sandbox isolation, leak a real
secret, or turn a decoy into an uncontrolled relay.

Use GitHub private vulnerability reporting for this repository. Do not attach
live malware, private keys, production `.env` files, packet captures containing
private traffic, or unredacted logs to a public issue.

Supported security fixes target the current `main` branch.

`scripts/check-public-leaks.py` enforces the "leak a real secret" half of this
policy on every change, and fails CI on private keys, GitHub/AWS/Slack tokens,
literal credential assignments, credentials embedded in URLs, deployment
`.env` files, private-key and packet-capture binaries, and the
deployment-specific addresses and default password this repository must never
name. Exactly one tracked `.env` is exempt, and it is the decoy honeyfs file
under `arcane/home/honeypot-cowrie/` that exists for attackers to find — not a
credential, and not something to "fix" by deleting.

Aikido AutoFix pull request settings live in `.aikido` at the repository root.
AutoFix pull requests are proposals and are never merged as-is; dependency
autofix stays enabled alongside Dependabot.
