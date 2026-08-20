# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-08-20

Since `0.1.0`, the codebase was split into `lib.rs`/`main.rs` and went through a security- and
correctness-focused pass. Highlights below; see git history for full detail.

### Security

- Fixed a path-traversal bug where `signum remove ..` (or similar) could resolve outside
  `~/.2fa` and delete unrelated directories. Profile names are now validated against an
  allowlist (`[A-Za-z0-9_-]`) instead of a blocklist of forbidden characters.
- The plaintext secret no longer touches disk at any point. It used to be written to a
  temporary file, encrypted in place, then securely deleted with `shred`; it's now piped
  directly into `gpg --encrypt` over the child process's stdin.
- Fixed `secure_remove_file` silently reporting success when `shred` spawned but exited
  non-zero, which could leave a plaintext secret on disk undetected. (Moot now that no
  plaintext file is ever created — see above.)
- The TOTP secret is no longer passed as a command-line argument to `add` (visible in shell
  history and `ps`/`/proc`). It's now prompted for interactively with hidden input.
- Decrypted secrets, and the secret typed into `add`, are wrapped in `zeroize::Zeroizing` so
  they're wiped from memory once they go out of scope.
- `~/.2fa`, profile directories, `config`, and `.secret.gpg` files are now created with
  restrictive permissions (`700`/`600` on Unix) instead of relying on umask.
- `remove` now asks for confirmation unless `--yes` is passed.

### Changed

- Replaced the `oathtool` shell-out with the `totp-rs` crate — one fewer runtime dependency,
  and TOTP generation is now unit-testable.
- `decrypt_secret` no longer passes `-r`/`-u` to `gpg --decrypt` (GPG resolves the key from
  the message itself); as a result, `token` no longer requires `configure` to have been run.
- Replaced the hand-rolled `SignumError` (`Display`/`Error`/`From` impls) with a
  `thiserror`-derived enum; `Io`/`Utf8` now carry `#[from]` so the underlying cause is
  preserved in the error chain.
- Replaced hand-parsed `env::args()` CLI dispatch with `clap`'s derive API — subcommands now
  get `--help`/`--version` for free, and an unknown subcommand exits with status 2 instead of
  status 0.
- `main()` now returns `anyhow::Result<()>`, replacing manual `eprintln!`/`process::exit`.
- `list_profiles` now uses `DirEntry::file_type()` instead of an extra `fs::metadata` call per
  entry, skips unreadable entries with a warning instead of aborting the whole listing, and
  only reports a directory as a profile if it actually contains `.secret.gpg`.
- `ensure_wd`/`create_profile` now create their directories atomically instead of a
  check-then-create race (TOCTOU).
- Added `SignumManager::with_work_dir` so tests (and any future embedding) don't need a real
  `~/.2fa`.

### Fixed

- `configure` now trims and rejects empty `user_id`/`key_id` input before validating the GPG
  key, instead of validating the raw (newline-terminated) input from `read_line`.
- Broadened the profile-name allowlist to include `.`, `@`, and `:` (still excluding `/` and
  `\`, and still rejecting `.`/`..` exactly) — the initial `[A-Za-z0-9_-]`-only allowlist broke
  real-world profile names such as email addresses (`user@example.com`) or
  `user@example.com:service`.
- `token` now accepts secrets under RFC 4226's 128-bit recommended minimum (`totp-rs`'s
  `build()` rejected these; switched to `build_noncompliant()`), and normalizes lowercase
  letters, internal whitespace, and `=` padding before decoding — restoring the leniency
  `oathtool -b` had, which some already-stored real-world secrets depend on.

### Added

- Unit tests for profile-name validation, TOTP encode/decode edge cases, and config error
  paths, plus an opt-in (`#[ignore]`d) integration test that exercises a real ephemeral GPG
  key end-to-end (`cargo test -- --ignored`).
- CI now runs `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` ahead of
  build/test.
- `Cargo.toml` gained `description`, `license`, `repository`, and `rust-version`.

## [0.1.0]

Initial release: GPG-encrypted TOTP profile storage under `~/.2fa`, with `configure`, `add`,
`list`, `remove`, and `token` commands, and TOTP codes generated via `oathtool`.
