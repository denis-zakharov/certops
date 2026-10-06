mod bundle;
mod text;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bundle::{Bundle, Format, certs_to_pem, detect_format, key_to_pem};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Inspect and convert certificate keystores (PEM and PKCS12)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print human readable information about certificates in a keystore
    Text {
        /// Keystore file (PEM or PKCS12)
        input: PathBuf,
        /// Print all available certificate information
        #[arg(long)]
        full: bool,
        /// PKCS12 password (asked interactively if omitted)
        #[arg(long)]
        password: Option<String>,
    },
    /// Convert between PEM and PKCS12 (format is detected from the input content)
    ///
    /// PKCS12 -> PEM writes <output>.pem (everything), <output>.cl.pem (chain),
    /// <output>.ca.pem (trusted certificates, if any) and <output>.key.pem (private key).
    /// PEM -> PKCS12 writes <output> as is.
    Export {
        /// Input keystore (PEM or PKCS12)
        input: PathBuf,
        /// Output file (PKCS12) or output prefix (PEM)
        output: PathBuf,
        /// PKCS12 password: used to read the input, or to protect the output
        /// (asked interactively if omitted)
        #[arg(long)]
        password: Option<String>,
        /// PEM -> PKCS12: additional PEM file with the private key (e.g. <name>.key.pem)
        #[arg(long)]
        key: Option<PathBuf>,
        /// PEM -> PKCS12: additional PEM file with trusted certificates (e.g. <name>.ca.pem)
        #[arg(long)]
        ca: Option<PathBuf>,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Text {
            input,
            full,
            password,
        } => {
            let bundle = Bundle::load(&input, || ask_password(password, false))?;
            print!("{}", text::render(&bundle, full)?);
        }
        Command::Export {
            input,
            output,
            password,
            key,
            ca,
        } => export(&input, &output, password, key, ca)?,
    }
    Ok(())
}

fn export(
    input: &Path,
    output: &Path,
    password: Option<String>,
    key: Option<PathBuf>,
    ca: Option<PathBuf>,
) -> Result<()> {
    let data = fs::read(input).with_context(|| format!("cannot read {}", input.display()))?;
    match detect_format(&data) {
        Format::Pkcs12 => {
            if key.is_some() || ca.is_some() {
                bail!("--key and --ca only apply when converting PEM to PKCS12");
            }
            let bundle = Bundle::from_pkcs12(&data, &ask_password(password, false)?)?;
            write_pem_files(&bundle, output)
        }
        Format::Pem => {
            let mut bundle = Bundle::from_pem(&data)?;
            // A bare PEM without a key holds only trusted certs; with --key they form the chain.
            if let Some(path) = key {
                let extra = Bundle::from_pem(&fs::read(path)?)?;
                if extra.key.is_none() {
                    bail!("no private key found in the --key file");
                }
                bundle.key = extra.key;
                bundle.chain.append(&mut bundle.trusted);
                bundle.chain.extend(extra.chain);
                bundle.chain.extend(extra.trusted);
            }
            if let Some(path) = ca {
                let extra = Bundle::from_pem(&fs::read(path)?)?;
                bundle.trusted.extend(extra.trusted);
                bundle.trusted.extend(extra.chain);
            }
            let password = ask_password(password, true)?;
            fs::write(output, bundle.to_pkcs12(&password)?)
                .with_context(|| format!("cannot write {}", output.display()))?;
            println!("wrote {}", output.display());
            Ok(())
        }
    }
}

fn write_pem_files(bundle: &Bundle, output: &Path) -> Result<()> {
    // Accept both "name" and "name.pem" as prefix.
    let prefix = match output.extension().and_then(|e| e.to_str()) {
        Some("pem") => output.with_extension(""),
        _ => output.to_path_buf(),
    };
    let named = |suffix: &str| {
        let mut s = prefix.clone().into_os_string();
        s.push(suffix);
        PathBuf::from(s)
    };

    let mut all = String::new();
    if let Some(k) = &bundle.key {
        all.push_str(&key_to_pem(k));
    }
    all.push_str(&certs_to_pem(bundle.all_certs()));
    write(&named(".pem"), &all)?;
    if !bundle.chain.is_empty() {
        write(&named(".cl.pem"), &certs_to_pem(&bundle.chain))?;
    }
    if !bundle.trusted.is_empty() {
        write(&named(".ca.pem"), &certs_to_pem(&bundle.trusted))?;
    }
    if let Some(k) = &bundle.key {
        write(&named(".key.pem"), &key_to_pem(k))?;
    }
    Ok(())
}

fn write(path: &Path, content: &str) -> Result<()> {
    fs::write(path, content).with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    if content.contains("PRIVATE KEY") {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    println!("wrote {}", path.display());
    Ok(())
}

fn ask_password(given: Option<String>, confirm: bool) -> Result<String> {
    if let Some(p) = given {
        return Ok(p);
    }
    let p = rpassword::prompt_password("PKCS12 password: ")?;
    if confirm && p != rpassword::prompt_password("Confirm password: ")? {
        bail!("passwords do not match");
    }
    Ok(p)
}

#[cfg(test)]
mod tests;
