# Agents

## Cursor Cloud specific instructions

### Project overview

Signum is a Rust CLI tool for managing TOTP 2FA secrets, encrypted with GPG. It stores profiles in `~/.2fa/`.

### Build / Test / Lint / Run

- **Build:** `cargo build`
- **Test:** `cargo test`
- **Lint:** `cargo clippy -- -W warnings`
- **Run:** `cargo run -- <command>` (e.g. `cargo run -- list`)

### External tool dependencies

The binary requires `gpg` (GnuPG) and `oathtool` (oath-toolkit) at runtime. Both are pre-installed in the Cloud Agent VM.

### Running the application end-to-end

To exercise the full add/token/remove flow you need a GPG key configured:

```sh
gpg --batch --passphrase '' --quick-gen-key "test@example.com" default default never
mkdir -p ~/.2fa
printf 'test@example.com\n<KEY_ID>\n' > ~/.2fa/config
```

Replace `<KEY_ID>` with the key ID from `gpg --list-keys --keyid-format long`.

After that, `cargo run -- add <name> <base32-secret>` will encrypt and store a secret, and `cargo run -- token <name>` will generate a TOTP code.
