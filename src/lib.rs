use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use thiserror::Error;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret};
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

/// Permissions restricted to the owner: `rwx` for directories, `rw` for files.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

pub const WORK_DIR: &str = ".2fa";
pub const CONFIG_FILENAME: &str = "config";
pub const SECRET_ENC_FILENAME: &str = ".secret.gpg";

#[derive(Debug, Error)]
pub enum SignumError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("output from an external command was not valid UTF-8: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("missing dependency: {0}")]
    MissingDependency(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("encryption error: {0}")]
    EncryptionError(String),
}

pub type Result<T> = std::result::Result<T, SignumError>;

/// Creates `path` as a directory restricted to the owner (mode 700 on Unix).
fn create_dir_secure(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        fs::DirBuilder::new().mode(DIR_MODE).create(path)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(path)?;
    }
    Ok(())
}

/// Creates or truncates `path` as a file restricted to the owner (mode 600 on Unix).
fn create_file_secure(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        Ok(fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(path)?)
    }
    #[cfg(not(unix))]
    {
        Ok(File::create(path)?)
    }
}

/// Creates `path` as a directory restricted to the owner, tolerating it
/// already existing.
fn ensure_dir_secure(path: &Path) -> Result<()> {
    match create_dir_secure(path) {
        Ok(()) => Ok(()),
        Err(SignumError::Io(e)) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

/// Restricts an already-created file to owner read/write (mode 600 on Unix).
/// Used for files created by an external process (e.g. `gpg --output`), whose
/// creation mode we cannot control directly.
fn restrict_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub struct SignumManager {
    work_dir: PathBuf,
    config: Option<HashMap<String, String>>,
}

impl SignumManager {
    pub fn new() -> Result<Self> {
        Self::with_work_dir(ensure_wd()?)
    }

    /// Like [`new`](Self::new), but stores profiles under `work_dir` instead
    /// of `~/.2fa`. Mainly useful for tests.
    pub fn with_work_dir(work_dir: PathBuf) -> Result<Self> {
        ensure_dir_secure(&work_dir)?;
        Ok(Self {
            work_dir,
            config: None,
        })
    }

    pub fn configure(&mut self, user_id: &str, key_id: &str) -> Result<()> {
        let user_id = user_id.trim();
        let key_id = key_id.trim();

        if user_id.is_empty() || key_id.is_empty() {
            return Err(SignumError::InvalidInput(
                "User ID and GPG key ID cannot be empty".to_string(),
            ));
        }

        validate_gpg_key(user_id, key_id)?;

        let mut config_path = self.work_dir.clone();
        config_path.push(CONFIG_FILENAME);

        let mut file = create_file_secure(&config_path)?;
        file.write_all(format!("{user_id}\n{key_id}").as_bytes())?;

        // Update in-memory config
        let mut config = HashMap::new();
        config.insert("user_id".to_string(), user_id.to_string());
        config.insert("key_id".to_string(), key_id.to_string());
        self.config = Some(config);

        Ok(())
    }

    pub fn list_profiles(&self) -> Result<Vec<String>> {
        let entries = fs::read_dir(&self.work_dir).map_err(|e| {
            SignumError::ConfigError(format!(
                "failed to read working directory {}: {}",
                self.work_dir.display(),
                e
            ))
        })?;
        let mut profiles = Vec::new();

        for entry in entries {
            // Skip individual unreadable entries rather than aborting the
            // whole listing.
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!(
                        "Warning: skipping unreadable entry in {}: {}",
                        self.work_dir.display(),
                        e
                    );
                    continue;
                }
            };

            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir {
                continue;
            }

            let Some(name_str) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };

            // Only directories holding an encrypted secret are profiles.
            let mut secret_path = entry.path();
            secret_path.push(SECRET_ENC_FILENAME);
            if secret_path.is_file() {
                profiles.push(name_str);
            }
        }

        Ok(profiles)
    }

    pub fn add_profile(&mut self, name: &str, secret: &str) -> Result<()> {
        self.validate_profile_name(name)?;
        self.ensure_config_loaded()?;

        let profile_path = self.create_profile(name)?;
        self.encrypt_secret(&profile_path, secret)?;

        Ok(())
    }

    pub fn remove_profile(&self, name: &str) -> Result<()> {
        self.validate_profile_name(name)?;

        let mut profile_path = self.work_dir.clone();
        profile_path.push(name);

        if !profile_path.exists() {
            return Err(SignumError::InvalidInput(format!(
                "Profile '{name}' does not exist"
            )));
        }

        fs::remove_dir_all(&profile_path)?;
        Ok(())
    }

    pub fn generate_token(&self, name: &str) -> Result<String> {
        self.validate_profile_name(name)?;

        let secret_enc_path = self.secret_enc_path(name);

        if !secret_enc_path.exists() {
            return Err(SignumError::InvalidInput(format!(
                "Profile '{name}' does not exist"
            )));
        }

        let secret = decrypt_secret(&secret_enc_path)?;
        self.generate_totp(&secret)
    }

    fn validate_profile_name(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(SignumError::InvalidInput(
                "Name cannot be empty".to_string(),
            ));
        }

        // Allowlist rather than blocklist: only characters that can never form
        // a path separator. This still permits names like an email address
        // ("user@example.com") or "user@example.com:service", both common in
        // practice. `/` and `\` are the only characters that could make a
        // name escape the profile directory, so excluding them from the
        // allowlist is what actually matters; "." and ".." are additionally
        // rejected by exact match below since they're the only other way a
        // single path segment can resolve somewhere unexpected.
        let is_valid = name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'));

        if !is_valid || name == "." || name == ".." {
            return Err(SignumError::InvalidInput(
                "Name can only contain letters, digits, '-', '_', '.', '@', ':', and must not be '.' or '..'".to_string(),
            ));
        }

        Ok(())
    }

    fn ensure_config_loaded(&mut self) -> Result<()> {
        if self.config.is_none() {
            self.config = Some(self.read_config()?);
        }
        Ok(())
    }

    fn create_profile(&self, name: &str) -> Result<PathBuf> {
        let mut path = self.work_dir.clone();
        path.push(name);

        match create_dir_secure(&path) {
            Ok(()) => Ok(path),
            Err(SignumError::Io(e)) if e.kind() == ErrorKind::AlreadyExists => Err(
                SignumError::InvalidInput(format!("Profile '{name}' already exists")),
            ),
            Err(e) => Err(e),
        }
    }

    /// Encrypts `secret` straight into `<profile_path>/SECRET_ENC_FILENAME`,
    /// piping it to `gpg` over stdin so the plaintext never touches disk.
    fn encrypt_secret(&self, profile_path: &Path, secret: &str) -> Result<()> {
        let config = self
            .config
            .as_ref()
            .ok_or_else(|| SignumError::ConfigError("Config not loaded".to_string()))?;

        let user_id = config
            .get("user_id")
            .ok_or_else(|| SignumError::ConfigError("user_id not found in config".to_string()))?;
        let key_id = config
            .get("key_id")
            .ok_or_else(|| SignumError::ConfigError("key_id not found in config".to_string()))?;

        let mut enc_path = PathBuf::from(profile_path);
        enc_path.push(SECRET_ENC_FILENAME);

        let mut child = Command::new("gpg")
            .arg("-r")
            .arg(user_id)
            .arg("-u")
            .arg(key_id)
            .arg("--encrypt")
            .arg("--output")
            .arg(&enc_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SignumError::EncryptionError("Failed to spawn gpg".to_string()))?;

        child
            .stdin
            .take()
            .ok_or_else(|| SignumError::EncryptionError("Failed to open gpg stdin".to_string()))?
            .write_all(secret.as_bytes())?;

        let status = child.wait()?;

        if !status.success() {
            return Err(SignumError::EncryptionError(
                "GPG encryption failed".to_string(),
            ));
        }

        restrict_file_permissions(&enc_path)?;
        Ok(())
    }

    fn generate_totp(&self, secret: &str) -> Result<String> {
        // `oathtool -b` (this crate's predecessor for TOTP generation) accepted
        // lowercase letters, internal whitespace (some services display
        // secrets grouped as "abcd efgh ..."), and trailing '=' padding.
        // totp-rs's decoder is strict RFC 4648, so normalize first to accept
        // the same real-world secrets oathtool did.
        let normalized = secret
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>()
            .to_uppercase();
        let normalized = normalized.trim_end_matches('=');

        let secret = TotpSecret::try_from_base32(normalized)
            .map_err(|e| SignumError::InvalidInput(format!("Invalid TOTP secret: {e}")))?;

        // `build()` enforces RFC 4226's 128-bit minimum secret length, but
        // real-world TOTP secrets (as issued by some services, and as
        // previously accepted without complaint by `oathtool`) are sometimes
        // shorter than that. `build_noncompliant()` skips that validation
        // while keeping the same SHA1/6-digit/30s defaults.
        let totp = TotpBuilder::new().with_secret(secret).build_noncompliant();

        Ok(totp.generate_current().to_string())
    }

    fn secret_enc_path(&self, name: &str) -> PathBuf {
        let mut path = self.work_dir.clone();
        path.push(name);
        path.push(SECRET_ENC_FILENAME);
        path
    }

    fn read_config(&self) -> Result<HashMap<String, String>> {
        let mut path = self.work_dir.clone();
        path.push(CONFIG_FILENAME);

        if !path.exists() {
            return Err(SignumError::ConfigError(
                "Configuration file not found. Run 'configure' first.".to_string(),
            ));
        }

        let mut file = File::open(&path).map_err(|e| {
            SignumError::ConfigError(format!("failed to open {}: {}", path.display(), e))
        })?;
        let mut data = String::new();
        file.read_to_string(&mut data).map_err(|e| {
            SignumError::ConfigError(format!("failed to read {}: {}", path.display(), e))
        })?;

        let lines: Vec<&str> = data.lines().collect();
        if lines.len() < 2 {
            return Err(SignumError::ConfigError(
                "Invalid configuration file format".to_string(),
            ));
        }

        let mut config = HashMap::new();
        config.insert("user_id".to_string(), lines[0].trim().to_string());
        config.insert("key_id".to_string(), lines[1].trim().to_string());

        Ok(config)
    }
}

// Utility functions
pub fn ensure_wd() -> Result<PathBuf> {
    let mut wd = home::home_dir().ok_or_else(|| {
        SignumError::ConfigError("Could not determine home directory".to_string())
    })?;
    wd.push(WORK_DIR);

    ensure_dir_secure(&wd)?;
    Ok(wd)
}

pub fn ensure_gpg() -> Result<()> {
    match Command::new("gpg").arg("--version").output() {
        Ok(_) => Ok(()),
        Err(_) => Err(SignumError::MissingDependency("gpg".to_string())),
    }
}

/// Decrypts `secret_enc_path` with GPG. No `-r`/`-u` flags are needed: GPG
/// selects the decryption key from the message itself, not from arguments.
fn decrypt_secret(secret_enc_path: &Path) -> Result<Zeroizing<String>> {
    let output = Command::new("gpg")
        .arg("--quiet")
        .arg("--decrypt")
        .arg(secret_enc_path)
        .output()
        .map_err(|_| SignumError::EncryptionError("Failed to decrypt secret".to_string()))?;

    if !output.status.success() {
        return Err(SignumError::EncryptionError(
            "GPG decryption failed".to_string(),
        ));
    }

    // Trim whitespace in place (no intermediate un-zeroized copy) before the
    // secret is wrapped for automatic zeroization on drop.
    let mut raw = output.stdout;
    while matches!(raw.last(), Some(b) if b.is_ascii_whitespace()) {
        raw.pop();
    }
    while matches!(raw.first(), Some(b) if b.is_ascii_whitespace()) {
        raw.remove(0);
    }

    Ok(Zeroizing::new(String::from_utf8(raw)?))
}

fn validate_gpg_key(user_id: &str, key_id: &str) -> Result<()> {
    let output = Command::new("gpg")
        .arg("--list-keys")
        .arg("--with-colons")
        .arg(user_id)
        .output()
        .map_err(|_| SignumError::ConfigError("Failed to list GPG keys".to_string()))?;

    if !output.status.success() {
        return Err(SignumError::ConfigError(format!(
            "GPG key '{user_id}' not found"
        )));
    }

    let keys = String::from_utf8(output.stdout)?;
    if !keys.contains(key_id) {
        return Err(SignumError::ConfigError(format!(
            "GPG key ID '{key_id}' not found"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> SignumManager {
        SignumManager {
            work_dir: PathBuf::from("/tmp/signum-test"),
            config: None,
        }
    }

    fn temp_manager() -> (tempfile::TempDir, SignumManager) {
        let dir = tempfile::tempdir().unwrap();
        let manager = SignumManager::with_work_dir(dir.path().to_path_buf()).unwrap();
        (dir, manager)
    }

    #[test]
    fn rejects_path_traversal_names() {
        let m = manager();
        assert!(m.validate_profile_name("..").is_err());
        assert!(m.validate_profile_name(".").is_err());
        assert!(m.validate_profile_name("../etc").is_err());
        assert!(m.validate_profile_name("foo/../../etc").is_err());
    }

    #[test]
    fn rejects_separators_and_empty() {
        let m = manager();
        assert!(m.validate_profile_name("").is_err());
        assert!(m.validate_profile_name("a/b").is_err());
        assert!(m.validate_profile_name("a\\b").is_err());
    }

    #[test]
    fn accepts_reasonable_names() {
        let m = manager();
        assert!(m.validate_profile_name("github").is_ok());
        assert!(m.validate_profile_name("work-email").is_ok());
        assert!(m.validate_profile_name("personal_gmail").is_ok());
        assert!(m.validate_profile_name("Account123").is_ok());
    }

    #[test]
    fn accepts_email_like_names() {
        // Real-world profile names are often an email address, optionally
        // suffixed with ":service" (e.g. "user@example.com:gitlab.com").
        let m = manager();
        assert!(m.validate_profile_name("user@example.com").is_ok());
        assert!(m
            .validate_profile_name("user@example.com:gitlab.com")
            .is_ok());
        assert!(m.validate_profile_name("user.name@example.com").is_ok());
    }

    #[test]
    fn generate_totp_produces_six_digits_for_valid_base32() {
        let m = manager();
        // RFC 6238 test seed, base32-encoded.
        let token = m
            .generate_totp("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
            .unwrap();
        assert_eq!(token.len(), 6);
        assert!(token.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn generate_totp_rejects_invalid_base32() {
        let m = manager();
        assert!(m.generate_totp("not valid base32!!!").is_err());
    }

    #[test]
    fn generate_totp_normalizes_lowercase_whitespace_and_padding() {
        // Real-world secrets (and what `oathtool -b` used to accept) are
        // sometimes lowercase, grouped with spaces, and/or '='-padded.
        let m = manager();
        let canonical = m
            .generate_totp("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
            .unwrap();
        assert_eq!(
            m.generate_totp("krsx g5ct mvrx ezlu kn2x azls knsw g4tf oq")
                .unwrap(),
            canonical
        );
        assert_eq!(
            m.generate_totp("KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ======")
                .unwrap(),
            canonical
        );
    }

    #[test]
    fn add_profile_fails_without_config() {
        let (_dir, mut m) = temp_manager();
        let err = m
            .add_profile("github", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
            .unwrap_err();
        assert!(matches!(err, SignumError::ConfigError(_)));
    }

    #[test]
    fn add_profile_fails_with_malformed_config() {
        let (dir, mut m) = temp_manager();
        fs::write(dir.path().join(CONFIG_FILENAME), "only-one-line").unwrap();
        let err = m
            .add_profile("github", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
            .unwrap_err();
        assert!(matches!(err, SignumError::ConfigError(_)));
    }

    #[test]
    fn list_profiles_ignores_non_profile_entries() {
        let (dir, m) = temp_manager();
        fs::write(dir.path().join(CONFIG_FILENAME), "user\nkey").unwrap();
        fs::create_dir(dir.path().join("not-a-profile")).unwrap(); // no .secret.gpg inside
        assert!(m.list_profiles().unwrap().is_empty());
    }

    #[test]
    fn remove_profile_fails_for_unknown_name() {
        let (_dir, m) = temp_manager();
        let err = m.remove_profile("nonexistent").unwrap_err();
        assert!(matches!(err, SignumError::InvalidInput(_)));
    }

    /// Full add -> token -> remove round trip against a real `gpg` binary
    /// with an ephemeral, disposable keyring. Not run by default, since it
    /// spawns real `gpg` processes and mutates the `GNUPGHOME` env var for
    /// the whole process: `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn add_and_generate_token_roundtrip_with_real_gpg() {
        if Command::new("gpg").arg("--version").output().is_err() {
            eprintln!("skipping: gpg not found on PATH");
            return;
        }

        let gnupg_home = tempfile::tempdir().unwrap();
        std::env::set_var("GNUPGHOME", gnupg_home.path());

        let keygen = Command::new("gpg")
            .args([
                "--batch",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Signum Test <test@example.com>",
                "default",
                "default",
                "never",
            ])
            .output()
            .unwrap();
        assert!(
            keygen.status.success(),
            "key generation failed: {}",
            String::from_utf8_lossy(&keygen.stderr)
        );

        let list = Command::new("gpg")
            .args(["--list-keys", "--with-colons"])
            .output()
            .unwrap();
        let list_str = String::from_utf8(list.stdout).unwrap();
        let key_id = list_str
            .lines()
            .find(|l| l.starts_with("fpr:"))
            .and_then(|l| l.split(':').nth(9))
            .unwrap()
            .to_string();

        let (_dir, mut m) = temp_manager();
        m.configure("test@example.com", &key_id).unwrap();
        m.add_profile("github", "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ")
            .unwrap();

        assert_eq!(m.list_profiles().unwrap(), vec!["github".to_string()]);

        let token = m.generate_token("github").unwrap();
        assert_eq!(token.len(), 6);
        assert!(token.chars().all(|c| c.is_ascii_digit()));

        m.remove_profile("github").unwrap();
        assert!(m.list_profiles().unwrap().is_empty());
    }
}
