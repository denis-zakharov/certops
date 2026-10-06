//! Human readable certificate output.

use std::fmt::Write;

use anyhow::{Result, anyhow};
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::bundle::Bundle;

pub fn render(bundle: &Bundle, full: bool) -> Result<String> {
    let mut out = String::new();
    if bundle.key.is_some() {
        writeln!(out, "Private key: present")?;
    }
    let sections = [("Chain", &bundle.chain), ("Trusted", &bundle.trusted)];
    let mut n = 0;
    for (label, certs) in sections {
        for der in certs {
            n += 1;
            writeln!(out, "\n[{n}] {label} certificate")?;
            out.push_str(&describe(der, full)?);
        }
    }
    if n == 0 {
        writeln!(out, "No certificates found")?;
    }
    Ok(out)
}

fn describe(der: &[u8], full: bool) -> Result<String> {
    let (_, cert) = parse_x509_certificate(der).map_err(|e| anyhow!("invalid certificate: {e}"))?;
    let mut out = String::new();
    let v = cert.validity();
    writeln!(out, "  Subject:    {}", cert.subject())?;
    writeln!(out, "  Issuer:     {}", cert.issuer())?;
    writeln!(out, "  Not before: {}", v.not_before)?;
    writeln!(
        out,
        "  Not after:  {}{}",
        v.not_after,
        if v.is_valid() {
            ""
        } else {
            "  (EXPIRED or not yet valid)"
        }
    )?;
    let sans = sans(&cert);
    if !sans.is_empty() {
        writeln!(out, "  SANs:       {}", sans.join(", "))?;
    }
    if !full {
        return Ok(out);
    }

    writeln!(out, "  Version:    {}", cert.version())?;
    writeln!(out, "  Serial:     {}", cert.raw_serial_as_string())?;
    writeln!(
        out,
        "  Signature:  {}",
        oid_name(&cert.signature_algorithm.algorithm)
    )?;
    let spki = cert.public_key();
    let key_info = match spki.parsed() {
        Ok(PublicKey::RSA(rsa)) => format!("RSA, {} bits", rsa.key_size()),
        Ok(PublicKey::EC(ec)) => format!("EC, {} bits", ec.key_size()),
        _ => oid_name(&spki.algorithm.algorithm),
    };
    writeln!(out, "  Public key: {key_info}")?;
    writeln!(out, "  SHA-256:    {}", fingerprint(der))?;
    writeln!(out, "  Extensions:")?;
    if cert.extensions().is_empty() {
        writeln!(out, "    (none)")?;
    }
    for ext in cert.extensions() {
        let crit = if ext.critical { " (critical)" } else { "" };
        match ext.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => {
                let path = bc
                    .path_len_constraint
                    .map(|p| format!(", pathlen {p}"))
                    .unwrap_or_default();
                writeln!(out, "    Basic Constraints{crit}: CA={}{path}", bc.ca)?
            }
            ParsedExtension::KeyUsage(ku) => writeln!(out, "    Key Usage{crit}: {ku}")?,
            ParsedExtension::ExtendedKeyUsage(eku) => {
                let mut names = vec![];
                for (set, name) in [
                    (eku.any, "any"),
                    (eku.server_auth, "serverAuth"),
                    (eku.client_auth, "clientAuth"),
                    (eku.code_signing, "codeSigning"),
                    (eku.email_protection, "emailProtection"),
                    (eku.time_stamping, "timeStamping"),
                    (eku.ocsp_signing, "OCSPSigning"),
                ] {
                    if set {
                        names.push(name.to_string());
                    }
                }
                names.extend(eku.other.iter().map(|o| o.to_string()));
                writeln!(out, "    Extended Key Usage{crit}: {}", names.join(", "))?
            }
            ParsedExtension::SubjectKeyIdentifier(k) => {
                writeln!(out, "    Subject Key Identifier{crit}: {k:x}")?
            }
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                let id = a
                    .key_identifier
                    .as_ref()
                    .map(|k| format!("{k:x}"))
                    .unwrap_or_default();
                writeln!(out, "    Authority Key Identifier{crit}: {id}")?
            }
            ParsedExtension::SubjectAlternativeName(_) => {
                writeln!(out, "    Subject Alternative Name{crit}: see SANs")?
            }
            ParsedExtension::CRLDistributionPoints(c) => {
                writeln!(out, "    CRL Distribution Points{crit}:")?;
                for dp in c.iter() {
                    writeln!(out, "      {:?}", dp.distribution_point)?;
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                writeln!(out, "    Authority Info Access{crit}:")?;
                for d in aia.iter() {
                    writeln!(
                        out,
                        "      {}: {}",
                        oid_name(&d.access_method),
                        general_name(&d.access_location)
                    )?;
                }
            }
            other => writeln!(out, "    {}{crit}: {other:?}", oid_name(&ext.oid))?,
        }
    }
    Ok(out)
}

fn sans(cert: &X509Certificate) -> Vec<String> {
    match cert.subject_alternative_name() {
        Ok(Some(san)) => san.value.general_names.iter().map(general_name).collect(),
        _ => vec![],
    }
}

fn general_name(n: &GeneralName) -> String {
    match n {
        GeneralName::DNSName(d) => format!("DNS:{d}"),
        GeneralName::RFC822Name(e) => format!("email:{e}"),
        GeneralName::URI(u) => format!("URI:{u}"),
        GeneralName::IPAddress(b) => match b.len() {
            4 => format!("IP:{}", std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            16 => format!(
                "IP:{}",
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).unwrap())
            ),
            _ => format!("IP:{}", hex::encode(b)),
        },
        other => format!("{other}"),
    }
}

fn fingerprint(der: &[u8]) -> String {
    let h = hex::encode_upper(Sha256::digest(der));
    h.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":")
}

fn oid_name(oid: &x509_parser::der_parser::oid::Oid) -> String {
    x509_parser::oid_registry::OidRegistry::default()
        .with_all_crypto()
        .with_x509()
        .get(oid)
        .map(|e| e.sn().to_string())
        .unwrap_or_else(|| oid.to_id_string())
}
