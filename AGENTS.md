# AGENTS.md

> Agent instructions for bpf-rbacd — Role-Based Access Control daemon for eBPF (Rust).

## Quick Reference

| Task | Command |
|------|---------|
| Build | `cargo build --workspace` |
| Format | `cargo fmt --all -- --check` |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| Unit tests | `cargo test --lib` |
| Doc tests | `cargo test --doc` |
| Integration tests | `cargo test --test integration` |
| Documentation | `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items` |
| Build eBPF | `cd bpf-rbacd-ebpf && cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release` |

## Project Structure

| Path | Purpose |
|------|---------|
| `src/main.rs` | Daemon entry point (proxy mode accept loop) |
| `src/lib.rs` | Crate root, re-exports modules |
| `src/policy.rs` | Policy engine (YAML parsing, permission checks, bitmaps) |
| `src/protocol.rs` | Client-daemon wire protocol (bincode over Unix socket) |
| `src/namespace.rs` | Namespace delegation (setns, bpffs mounting, tokens) |
| `src/bin/bpf-rbac.rs` | CLI client (clap, supports both flag and positional args) |
| `bpf-rbacd-common/` | Shared `#[repr(C)]` types for the eBPF map (`no_std`) |
| `bpf-rbacd-ebpf/` | eBPF LSM programs (separate workspace, `bpfel-unknown-none`) |
| `config/policy.yaml` | Example RBAC policy |
| `tests/integration.rs` | Integration and unit test suite |
| `docs/DESIGN.md` | Design proposal |
| `docs/DEVELOPMENT.md` | Developer walkthrough |

## Two Workspaces

The eBPF crate (`bpf-rbacd-ebpf/`) targets `bpfel-unknown-none` — a bare-metal
BPF target with no `std`. It is excluded from the root workspace via
`exclude = ["bpf-rbacd-ebpf"]`. Never build both in a single `cargo`
invocation.

## Coding Conventions

- **Edition:** Rust 2021 (MSRV 1.85).
- **Formatting:** `cargo fmt` (rustfmt defaults). CI enforces `--check`.
- **Linting:** `cargo clippy` with `-D warnings`. Zero warnings policy.
- **Errors:** `anyhow::Result` in binaries. Error messages should be
  actionable — tell the user what went wrong and what to try.
- **Documentation:** All public items must have doc comments. Avoid
  `<angle_brackets>` and `[square_brackets]` in doc comments — rustdoc
  interprets them as HTML tags and intra-doc links.
- **Commits:** Use conventional prefixes: `fix:`, `feat:`, `doc:`, `ci:`,
  `refactor:`, `test:`
- **Search:** Always exclude `target/` directories when searching.

## Testing

- Tests marked `#[ignore]` require root and/or `CAP_BPF`. Do not remove
  the ignore attribute; CI runners cannot execute them.
- Run privileged tests locally: `sudo -E cargo test -- --ignored`

## Things to Watch Out For

- The CLI (`src/bin/bpf-rbac.rs`) supports both `--flag` and positional
  arg syntax. Do not break either.
- `bpf-rbacd-common` must compile as `no_std` (eBPF target) and with `std`
  (via the `user` feature). Be careful with dependencies.
- Kernel constants (program types, map types, commands) become bitmap bit
  positions — they must match the kernel's enum values exactly.
- Policy engine is allow-list only and fails closed. Effective permissions
  are the intersection of the role policy and the system policy.
