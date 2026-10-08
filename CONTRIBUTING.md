# Contributing to sverb

- Read [`SPEC.md`](SPEC.md) for what sverb is meant to do and
  [`docs/architecture.md`](docs/architecture.md) for how the crates fit together.
- Run the checks listed in the README's **Checks** section before sending a change.

## Logging

sverb has a strict logging policy: no hostnames, addresses, usernames, commands, snippet
bodies or item labels at `info` and above, and secrets never, at any level. Read
[`docs/logging.md`](docs/logging.md) before adding a `tracing` call, and use the
review checklist at the end of it.
