mod bundle;
mod jks;
mod text;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use bundle::{Bundle, Format, certs_to_pem, detect_format, key_to_encrypted_pem, key_to_pem};
use clap::{Parser, Subcommand, ValueEnum};

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
        /// Keystore file (PEM, PKCS12 or JKS)
        input: PathBuf,
        /// Print all available certificate information
        #[arg(long)]
        full: bool,
        /// Keystore password (asked interactively if omitted)
        #[arg(long)]
        password: Option<String>,
    },
    /// Convert between PEM, PKCS12 and JKS (input format is detected from its content)
    ///
    /// To PEM writes <output>.pem (everything), <output>.cl.pem (chain),
    /// <output>.ca.pem (trusted certificates, if any) and <output>.key.pem (private key).
    /// To PKCS12 or JKS writes <output> as is.
    ///
    /// The target format is taken from --to, else from the output extension
    /// (.jks, .p12/.pfx), else it is PKCS12 for PEM input and PEM otherwise.
    Export {
        /// Input keystore (PEM, PKCS12 or JKS)
        input: PathBuf,
        /// Output file (PKCS12, JKS) or output prefix (PEM)
        output: PathBuf,
        /// Target format
        #[arg(long, value_enum)]
        to: Option<Target>,
        /// Password to read the input and, unless --out-password is given, to protect the
        /// output (asked interactively if omitted)
        #[arg(long)]
        password: Option<String>,
        /// Password protecting a PKCS12/JKS output
        #[arg(long)]
        out_password: Option<String>,
        /// PEM output: write the private key unencrypted (default: encrypted with the
        /// output password)
        #[arg(long)]
        noenc: bool,
        /// PEM input: additional PEM file with the private key (e.g. <name>.key.pem)
        #[arg(long)]
        key: Option<PathBuf>,
        /// PEM input: additional PEM file with trusted certificates (e.g. <name>.ca.pem)
        #[arg(long)]
        ca: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Target {
    Pem,
    P12,
    Jks,
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
            mut password,
        } => {
            let bundle = Bundle::load(&input, || ask_password(&mut password, false))?;
            print!("{}", text::render(&bundle, full)?);
        }
        Command::Export {
            input,
            output,
            to,
            password,
            out_password,
            noenc,
            key,
            ca,
        } => export(&input, &output, to, password, out_password, noenc, key, ca)?,
    }
    Ok(())
}

fn infer_target(output: &Path, input: Format) -> Target {
    match output.extension().and_then(|e| e.to_str()) {
        Some("jks") => Target::Jks,
        Some("p12" | "pfx") => Target::P12,
        _ if input == Format::Pem => Target::P12,
        _ => Target::Pem,
    }
}

#[allow(clippy::too_many_arguments)]
fn export(
    input: &Path,
    output: &Path,
    to: Option<Target>,
    password: Option<String>,
    out_password: Option<String>,
    noenc: bool,
    key: Option<PathBuf>,
    ca: Option<PathBuf>,
) -> Result<()> {
    let data = fs::read(input).with_context(|| format!("cannot read {}", input.display()))?;
    let format = detect_format(&data);
    let target = to.unwrap_or_else(|| infer_target(output, format));
    if format != Format::Pem && (key.is_some() || ca.is_some()) {
        bail!("--key and --ca only apply to PEM input");
    }
    if noenc && target != Target::Pem {
        bail!("--noenc only applies to PEM output");
    }

    let mut in_password = password.clone();
    let mut ask_in = || ask_password(&mut in_password, false);
    let mut bundle = match format {
        Format::Pkcs12 => Bundle::from_pkcs12(&data, &ask_in()?)?,
        Format::Jks => Bundle::from_jks(&data, &ask_in()?)?,
        Format::Pem => Bundle::from_pem_with(&data, &mut ask_in)?,
    };
    // A bare PEM without a key holds only trusted certs; with --key they form the chain.
    if let Some(path) = key {
        let extra = Bundle::from_pem_with(&fs::read(path)?, &mut ask_in)?;
        if extra.key.is_none() {
            bail!("no private key found in the --key file");
        }
        bundle.key = extra.key;
        bundle.chain.append(&mut bundle.trusted);
        bundle.chain.extend(extra.chain);
        bundle.chain.extend(extra.trusted);
    }
    if let Some(path) = ca {
        let extra = Bundle::from_pem_with(&fs::read(path)?, &mut ask_in)?;
        bundle.trusted.extend(extra.trusted);
        bundle.trusted.extend(extra.chain);
    }

    let mut out_pw = out_password.or(password);
    if target == Target::Pem {
        let key_pw = if bundle.key.is_some() && !noenc {
            Some(ask_password(&mut out_pw, true)?)
        } else {
            None
        };
        return write_pem_files(&bundle, output, key_pw.as_deref());
    }
    let out_pw = ask_password(&mut out_pw, true)?;
    let encoded = match target {
        Target::Jks => bundle.to_jks(&out_pw)?,
        _ => bundle.to_pkcs12(&out_pw)?,
    };
    fs::write(output, encoded).with_context(|| format!("cannot write {}", output.display()))?;
    println!("wrote {}", output.display());
    Ok(())
}

/// Writes the PEM file set; the private key is encrypted when `key_password` is given.
fn write_pem_files(bundle: &Bundle, output: &Path, key_password: Option<&str>) -> Result<()> {
    let key_pem = |k: &[u8]| match key_password {
        Some(pw) => key_to_encrypted_pem(k, pw),
        None => Ok(key_to_pem(k)),
    };
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
        all.push_str(&key_pem(k)?);
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
        write(&named(".key.pem"), &key_pem(k)?)?;
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

/// Returns the given password, or prompts for it (with confirmation when `confirm` is set).
fn ask_password(given: &mut Option<String>, confirm: bool) -> Result<String> {
    if let Some(p) = given {
        return Ok(p.clone());
    }
    let p = rpassword::prompt_password("Password: ")?;
    if confirm && p != rpassword::prompt_password("Confirm password: ")? {
        bail!("passwords do not match");
    }
    *given = Some(p.clone());
    Ok(p)
}

#[cfg(test)]
mod tests;
