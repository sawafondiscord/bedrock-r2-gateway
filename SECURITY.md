# Security

This project validates short-lived signed Bedrock proofs. It is not a live
session introspection endpoint. See the README's security model before deployment.

Never include license keys, passwords, signed responses, session tokens,
production configuration or private bucket files in issues or pull requests.
Use GitHub private vulnerability reporting if the repository owner has enabled
it. Otherwise ask the maintainer for a private channel without posting exploit
credentials or sensitive files publicly.

There is no claim of an independent security audit. Production acceptance must
include a real signed response from the configured Bedrock system, denied and
expired responses, and verification that the R2 bucket has no public access.
