# Contributing Guide

* [New Contributor Guide](#contributing-guide)
  * [Ways to Contribute](#ways-to-contribute)
  * [Find an Issue](#find-an-issue)
  * [Ask for Help](#ask-for-help)
  * [Pull Request Lifecycle](#pull-request-lifecycle)
  * [Pull Request Checklist](#pull-request-checklist)
  * [Development Environment](#development-environment)

Welcome! We are glad that you want to contribute to bpf-rbacd! 💖

As you get started, you are in the best position to give us feedback on areas of
our project that we need help with including:

* Problems found during setting up a new developer environment
* Gaps in our documentation
* Bugs in our automation scripts

If anything doesn't make sense, or doesn't work when you run it, please open a
bug report and let us know!

## Ways to Contribute

We welcome many different types of contributions including:

* New features
* Bug fixes
* Documentation
* Builds, CI/CD
* Issue triage
* Testing (especially on different kernel versions)
* Policy examples and use cases
* Release management

Not everything happens through a GitHub pull request. Please open an issue to
discuss how we can work together.

## Find an Issue

Issues labelled as ["good first issue"] are suitable for new
contributors. They provide extra information to help you make your first
contribution.

Issues labelled as ["help wanted"] are usually more difficult. We
recommend them for people who have either made some contributions already or
feel comfortable with starting from more demanding tasks.

Sometimes there won't be any issues with these labels. That's ok! There is
likely still something for you to work on. If you want to contribute but you
don't know where to start or can't find a suitable issue, feel free to open an
issue and ask.

Once you see an issue that you'd like to work on, please post a comment saying
that you want to work on it. Something like "I want to work on this" is fine.

## Ask for Help

The best way to reach us with a question when contributing is to ask on the
original GitHub issue.

## Pull Request Lifecycle

1. When you open a PR a maintainer will be assigned for review
2. Make sure that your PR is passing CI — if you need help with failing checks
   please feel free to ask!
3. Once it is passing all CI checks, a maintainer will review your PR and you
   may be asked to make changes
4. When you have received an approval, your PR will be merged

In some cases, other changes may conflict with your PR. If this happens, you
will need to rebase your branch on top of `main`.

## Logical Grouping of Commits

It is a recommended best practice to keep your changes as logically grouped as
possible within individual commits. If while you're developing you prefer doing
a number of commits that are "checkpoints" and don't represent a single logical
change, please squash those together before asking for a review.
When addressing review comments, please perform an interactive rebase and edit
commits directly rather than adding new commits with messages like
"Fix review comments".

## Commit Message Guidelines

A good commit message should describe what changed and why.

1. The first line should:
   * Contain a short description of the change (preferably 50 characters or
     less, and no more than 72 characters)
   * Be entirely in lowercase with the exception of proper nouns, acronyms, and
     the words that refer to code, like function/variable names
   * Be prefixed with the area being changed

   Examples:
   * `fix: implement flag-based CLI parsing for create-map`
   * `doc: add CI pipeline section to developer guide`
   * `ci: install bpf-linker, fix clippy needless borrows`

2. Keep the second line blank.
3. Wrap all other lines at 72 columns (except for long URLs).
4. If your patch fixes an open issue, you can add a reference to it at the end
   of the log. Use the `Closes: #` prefix and the issue number.

   Example:

   ```txt
   fix: implement flag-based CLI parsing for create-map

   The README documented --type/--name/--key-size flags, but the CLI
   only accepted positional arguments. Replace manual arg parsing with
   clap, supporting both flag and positional syntax for backward
   compatibility.

   Closes: #9
   ```

## Pull Request Checklist

When you submit your pull request, or you push new commits to it, our automated
systems will run some checks on your new code. We require that your pull request
passes these checks. It is recommended that you run the checks locally before
submitting. See [Running CI Checks Locally](#running-ci-checks-locally) below.

## Development Environment

### Prerequisites

* Linux kernel 6.1+ with `CONFIG_BPF_SYSCALL=y`
* Rust 1.85+ (stable) and nightly (for the eBPF crate)
* `CONFIG_DEBUG_INFO_BTF=y` for BTF/CO-RE support

See the [README](README.md#building) for full build instructions and the
[Developer Guide](docs/DEVELOPMENT.md) for a walkthrough of the codebase.

### Building

```bash
# Main workspace
cargo build

# eBPF programs (needs nightly + rust-src + bpf-linker)
cd bpf-rbacd-ebpf
cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release
```

### Running CI Checks Locally

```bash
# Format
cargo fmt --all -- --check

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Tests
cargo test --lib
cargo test --doc
cargo test --test integration

# Documentation
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items
```

### Privileged Tests

Tests marked `#[ignore]` require root and/or `CAP_BPF`. These don't run in
GitHub Actions. To run them locally:

```bash
sudo -E cargo test -- --ignored
```

## License

By contributing, you agree that your contributions will be dual-licensed under
MIT and Apache 2.0, consistent with the project's existing license terms. See
[LICENSE-MIT](LICENSE-MIT) and [LICENSE-APACHE](LICENSE-APACHE).

["good first issue"]: https://github.com/danielmellado/bpf-rbacd/labels/good%20first%20issue
["help wanted"]: https://github.com/danielmellado/bpf-rbacd/labels/help%20wanted
