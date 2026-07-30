---
description: Caveats on all Rust source files
globs: "**/*.rs"
alwaysApply: false
---

# Caveats

Follow these principles when authoring:

## Rules

Do *not*:

- Pull in an async app runtime, Hyper, Axum, Tower, or serde as architecture
- Block reactor threads on disk, DNS, or app logic
- Block on parse-to-EOF ingress
- Materialise full wire messages as owned DOM objects on the hot path

Do:

- ask before introducing any new external dependency