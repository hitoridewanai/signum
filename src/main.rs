use std::collections::HashMap;
use std::fs::File;
use std::io::{stdin, stdout, Error, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, process};

const WORK_DIR: &str = ".2fa";
const CONFIG_FILENAME: &str = "config";
const SECRET_FILENAME: &str = ".secret";
const SECRET_ENC_FILENAME: &str = ".secret.gpg";

fn main() {
    ensure_arg_count(2);

    match arg(1).as_str() {
        "configure" => {
            configure();
        }

        "add" => {
            ensure_arg_count(4);
            ensure_gpg();
            add(&arg(2), &arg(3));
        }

        "remove" => {
            ensure_arg_count(3);
            remove(&arg(2));
        }

        "token" => {
            ensure_arg_count(3);
            ensure_gpg();
            token(&arg(2));
        }

        _ => {
            print_usage();
        }
    }
}

fn configure() {
    println!("Configuring...");

    let mut wd = ensure_wd().unwrap();

    let mut user_id = String::new();
    let mut kid = String::new();

    print!("Please input user ID/e-mail: ");
    stdout().flush().unwrap();
    read_user_input(&mut user_id);

    print!("Please input GPG key ID: ");
    stdout().flush().unwrap();
    read_user_input(&mut kid);

    wd.push(CONFIG_FILENAME);

    let mut file = File::create(&wd).unwrap();
    file.write_all(format!("{}{}", &user_id, &kid).as_bytes())
        .unwrap();

    println!("Configured!");
}

fn add(name: &str, secret: &str) {
    println!("Adding, name: {}, secret: {}", name, secret);

    let wd = ensure_wd().unwrap();
    let config = read_config(&wd).unwrap();

    let profile_path = create_profile(&wd, name).unwrap();
    let secret_path = store_secret(&profile_path, secret).unwrap();
    encrypt_secret(&secret_path, &config).unwrap();

    println!("Added, name: {}", name);

    token(name);
}

fn remove(name: &str) {
    println!("Removing, name: {}", name);
}

fn token(name: &str) {
    println!("Token, name: {}", name);

    let wd = ensure_wd().unwrap();
    let config = read_config(&wd).unwrap();
    let secret_enc_path = secret_enc_path(&wd, name);
    let secret = decrypt_secret(&secret_enc_path, &config).unwrap();

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("oathtool -b --totp '{}'", secret))
        .output()
        .unwrap();

    let token = String::from_utf8(output.stdout).unwrap();

    println!("{}", token);
}

fn decrypt_secret(secret_enc_path: &Path, config: &HashMap<&str, String>) -> Result<String, Error> {
    let user_id = config.get("user_id").unwrap();
    let key_id = config.get("key_id").unwrap();

    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "gpg --quiet -r {} -u {} --decrypt {:?}",
            user_id, key_id, secret_enc_path
        ))
        .output()?;

    let secret = String::from_utf8(output.stdout).unwrap();

    Result::Ok(secret)
}

fn encrypt_secret(secret_path: &Path, config: &HashMap<&str, String>) -> Result<(), Error> {
    let user_id = config.get("user_id").unwrap();
    let key_id = config.get("key_id").unwrap();

    Command::new("sh")
        .arg("-c")
        .arg(format!(
            "gpg -r {} -u {} --encrypt {:?}",
            user_id, key_id, secret_path
        ))
        .output()?;

    fs::remove_file(secret_path)?;

    Ok(())
}

fn store_secret(profile: &Path, secret: &str) -> Result<PathBuf, Error> {
    let mut path = PathBuf::from(profile);
    path.push(SECRET_FILENAME);

    let mut file = File::create(&path)?;
    file.write_all(secret.as_bytes())?;

    Result::Ok(path)
}

fn create_profile(wd: &Path, name: &str) -> Result<PathBuf, Error> {
    let mut path = PathBuf::from(wd);
    path.push(name);

    fs::create_dir(&path)?;

    Result::Ok(path)
}

fn ensure_wd() -> Result<PathBuf, Error> {
    let mut wd = home::home_dir().unwrap();
    wd.push(WORK_DIR);

    if !Path::new(&wd).exists() {
        println!("Creating working directory under {:?}", &wd);
        fs::create_dir(&wd)?;
    }

    Result::Ok(wd)
}

fn read_user_input(buffer: &mut String) {
    stdin().read_line(buffer).unwrap();
}

fn arg(nth: usize) -> String {
    std::env::args().nth(nth).unwrap()
}

fn ensure_arg_count(count: usize) {
    if std::env::args().len() < count {
        print_usage();
    }
}

fn secret_enc_path(wd: &Path, name: &str) -> PathBuf {
    let mut path = PathBuf::from(wd);
    path.push(name);
    path.push(SECRET_ENC_FILENAME);

    path
}

fn ensure_gpg() {
    // TODO: ensure
}

fn read_config(wd: &Path) -> Result<HashMap<&str, String>, Error> {
    let mut path = PathBuf::from(wd);
    path.push(CONFIG_FILENAME);

    let mut file = File::open(&path)?;

    let mut data = String::new();
    file.read_to_string(&mut data)?;

    let values: Vec<&str> = data.split('\n').collect();

    let user_id = String::from(values[0]);
    let key_id = String::from(values[1]);

    let mut config = HashMap::new();
    config.insert("user_id", user_id);
    config.insert("key_id", key_id);

    Result::Ok(config)
}

fn print_usage() {
    println!("Manage token-based multi-factor authentication");
    println!("\nUSAGE:");
    println!("\tsignum OPERATION ARGS");
    println!("\nOPERATIONS:");
    println!("\tconfigure | list | add | remove | token");
    println!("\nadd:");
    println!("\tname secret");
    println!("\nremove:");
    println!("\tname");
    println!("\ntoken:");
    println!("\tname");

    process::exit(1);
}
