# Signum - 2FA Token Manager

A secure command-line tool for managing Time-based One-Time Password (TOTP) tokens with GPG encryption.

## Features

- **Secure Storage**: Secrets are encrypted with your GPG key before they ever touch disk — the plaintext secret is piped directly into `gpg`, never written to a temporary file
- **Simple CLI**: Subcommands with `--help` on every command, built on `clap`
- **Profile Management**: Organize multiple 2FA accounts into named profiles
- **Cross-platform**: Works on Unix-like systems (Linux, macOS); owner-only file permissions (700/600) are enforced on Unix

## Prerequisites

- **GPG**: for encrypting/decrypting secrets. TOTP codes themselves are generated in-process (via the `totp-rs` crate) — no `oathtool` or other external TOTP tool is required.

### Installation

```bash
# On Ubuntu/Debian
sudo apt-get install gnupg

# On macOS
brew install gnupg

# On Arch Linux
sudo pacman -S gnupg
```

## Usage

```
signum <COMMAND>

Commands:
  configure  Configure the GPG identity used to encrypt and decrypt secrets
  list       List all configured profiles
  add        Add a new profile (prompts for the TOTP secret)
  remove     Remove a profile
  token      Generate a token for a profile
  help       Print this message or the help of the given subcommand(s)
```

Run `signum <command> --help` for a command's exact arguments.

### Initial Setup

1. **Configure GPG keys** (if not already done):
   ```bash
   gpg --gen-key
   ```

2. **Configure Signum**:
   ```bash
   signum configure
   ```
   You'll be prompted for:
   - User ID/email (for GPG key identification)
   - GPG key ID

### Managing 2FA Tokens

**Add a new 2FA account** (the secret is prompted for interactively, with hidden input — it is never passed as a command-line argument, so it never lands in shell history or `ps`):
```bash
signum add <profile_name>
# Secret (TOTP seed, base32): ********************
```

**Generate a token**:
```bash
signum token <profile_name>
```

**List all profiles**:
```bash
signum list
```

**Remove a profile** (asks for confirmation unless `--yes` is passed):
```bash
signum remove <profile_name>
signum remove <profile_name> --yes   # skip the confirmation prompt
```

### Example Workflow

```bash
# Configure the tool
signum configure
# Enter: user@example.com
# Enter: ABC123DEF456

# Add a GitHub 2FA account
signum add github
# Secret (TOTP seed, base32): JBSWY3DPEHPK3PXP

# Generate a token for GitHub
signum token github
# Output: 123456

# List all accounts
signum list
# Output: github
```

## Security Features

- **GPG encryption**: secrets are encrypted with your GPG key (`-r`/`-u`) before storage; decryption relies on GPG resolving the key from the message itself
- **No plaintext on disk**: the secret is piped directly into `gpg --encrypt` over stdin — there is no intermediate plaintext file at any point, and nothing to securely delete afterward
- **Memory hygiene**: decrypted secrets, and the secret typed into `add`, are wrapped in `zeroize::Zeroizing` so they're wiped from memory as soon as they go out of scope
- **Restrictive permissions**: `~/.2fa` and each profile directory are created mode `700`; `config` and each profile's `.secret.gpg` are mode `600` (enforced on Unix, not left to umask)
- **Path-traversal-safe profile names**: profile names are validated against an allowlist (`[A-Za-z0-9_-]`), not a blocklist, so names like `..` are rejected outright rather than pattern-matched against known-bad substrings
- **Destructive-action confirmation**: `remove` asks for confirmation unless `--yes` is passed
- **No secrets in argv**: the TOTP seed is always prompted for interactively (hidden input), never accepted as a CLI argument

### Security Considerations

- **GPG key security**: the security of your tokens depends on your GPG key's security
- **Backups**: `~/.2fa` is the entire state of the tool — back it up (it's already encrypted, so an encrypted backup destination isn't required, but treat the encrypted blobs as sensitive regardless)

## Building

```bash
cargo build --release
```

## Installation

```bash
# Install to system
cargo install --path .

# Or copy the binary
sudo cp target/release/signum /usr/local/bin/
```

## Development

```bash
cargo test                     # unit tests
cargo test -- --ignored        # also run the test that exercises a real gpg key
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

See `CHANGELOG.md` for a history of notable changes.

## License

MIT — see [LICENSE](LICENSE).
