//! In-memory representation of a keystore and its PEM / PKCS#12 (de)serialization.

use std::fs;
use std::path::Path;

use crate::jks;

use anyhow::{Context, Result, bail};
use p12_keystore::{
    Certificate, KeyStore, KeyStoreEntry, Pkcs12ImportPolicy, PrivateKey, PrivateKeyChain,
};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;

/// Everything a keystore can hold, as DER blobs.
#[derive(Debug, Default, Clone)]
pub struct Bundle {
    /// Private key, PKCS#8 DER.
    pub key: Option<Vec<u8>>,
    /// Certificate chain, leaf first.
    pub chain: Vec<Vec<u8>>,
    /// Standalone trusted certificates.
    pub trusted: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pem,
    Pkcs12,
    Jks,
}

/// Detects the format by content: JKS starts with a magic number, PEM is text with
/// `-----BEGIN`, anything else is assumed to be PKCS#12 (binary DER).
pub fn detect_format(data: &[u8]) -> Format {
    if data.starts_with(&crate::jks::MAGIC) {
        Format::Jks
    } else if data.windows(10).any(|w| w == b"-----BEGIN") {
        Format::Pem
    } else {
        Format::Pkcs12
    }
}

impl Bundle {
    pub fn from_pkcs12(data: &[u8], password: &str) -> Result<Self> {
        let store =
            KeyStore::from_pkcs12(data, password, Pkcs12ImportPolicy::Relaxed).map_err(|e| {
                anyhow::anyhow!("cannot read PKCS12 (wrong password or corrupt file?): {e}")
            })?;
        let mut bundle = Bundle::default();
        for (_, entry) in store.entries() {
            match entry {
                KeyStoreEntry::PrivateKeyChain(kc) => {
                    if bundle.key.is_none() {
                        bundle.key = Some(kc.key().as_der().to_vec());
                        bundle.chain = kc.certs().iter().map(|c| c.as_der().to_vec()).collect();
                    }
                }
                KeyStoreEntry::Certificate(c) => bundle.trusted.push(c.as_der().to_vec()),
                KeyStoreEntry::Secret(_) => {}
            }
        }
        Ok(bundle)
    }

    pub fn from_jks(data: &[u8], password: &str) -> Result<Self> {
        let jks = jks::parse(data, password)?;
        let (key, chain) = match jks.key {
            Some((k, c)) => (Some(k), c),
            None => (None, vec![]),
        };
        Ok(Bundle {
            key,
            chain,
            trusted: jks.trusted,
        })
    }

    pub fn to_jks(&self, password: &str) -> Result<Vec<u8>> {
        let key = match &self.key {
            Some(_) if self.chain.is_empty() => {
                bail!("a private key requires at least one certificate")
            }
            Some(k) => Some((k.clone(), self.chain.clone())),
            None => None,
        };
        // Without a key, JKS has no place for a chain: keep those certificates as trusted entries.
        let trusted = if key.is_some() {
            self.trusted.clone()
        } else {
            self.all_certs().cloned().collect()
        };
        jks::write(&jks::Jks { key, trusted }, password)
    }

    /// Parses PEM text. Certificates go to the chain when a key is present, otherwise to `trusted`.
    pub fn from_pem(data: &[u8]) -> Result<Self> {
        let mut certs = Vec::new();
        let mut key = None;
        for block in pem::parse_many(data).context("invalid PEM")? {
            match block.tag() {
                "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
                    certs.push(block.into_contents())
                }
                "PRIVATE KEY" => key = Some(block.into_contents()),
                "ENCRYPTED PRIVATE KEY" => {
                    bail!("encrypted PEM private keys are not supported; decrypt the key first")
                }
                "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                    bail!(
                        "legacy key format {:?} is not supported; convert it to PKCS#8 (`openssl pkcs8 -topk8 -nocrypt`)",
                        block.tag()
                    )
                }
                _ => {}
            }
        }
        Ok(match key {
            Some(_) => Bundle {
                key,
                chain: order_chain(certs),
                trusted: vec![],
            },
            None => Bundle {
                key: None,
                chain: vec![],
                trusted: certs,
            },
        })
    }

    pub fn load(path: &Path, password: impl FnOnce() -> Result<String>) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        match detect_format(&data) {
            Format::Pem => Self::from_pem(&data),
            Format::Pkcs12 => Self::from_pkcs12(&data, &password()?),
            Format::Jks => Self::from_jks(&data, &password()?),
        }
    }

    pub fn to_pkcs12(&self, password: &str) -> Result<Vec<u8>> {
        let mut store = KeyStore::new();
        if let Some(key) = &self.key {
            if self.chain.is_empty() {
                bail!("a private key requires at least one certificate");
            }
            let certs = self
                .chain
                .iter()
                .map(|c| Certificate::from_der(c))
                .collect::<Result<Vec<_>, _>>()?;
            let id = Sha256::digest(&self.chain[0])[..20].to_vec();
            let chain = PrivateKeyChain::new(id, PrivateKey::from_der(key)?, certs);
            store.add_entry("key", KeyStoreEntry::PrivateKeyChain(chain));
        } else {
            for (i, c) in self.chain.iter().enumerate() {
                store.add_entry(
                    &format!("cert-{}", i + 1),
                    KeyStoreEntry::Certificate(Certificate::from_der(c)?),
                );
            }
        }
        for (i, c) in self.trusted.iter().enumerate() {
            store.add_entry(
                &format!("ca-{}", i + 1),
                KeyStoreEntry::Certificate(Certificate::from_der(c)?),
            );
        }
        Ok(store.writer(password).write()?)
    }

    /// Every certificate: chain first, then trusted ones.
    pub fn all_certs(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.chain.iter().chain(&self.trusted)
    }
}

pub fn certs_to_pem<'a>(certs: impl IntoIterator<Item = &'a Vec<u8>>) -> String {
    certs
        .into_iter()
        .map(|c| pem::encode(&pem::Pem::new("CERTIFICATE", c.clone())))
        .collect()
}

pub fn key_to_pem(key: &[u8]) -> String {
    pem::encode(&pem::Pem::new("PRIVATE KEY", key.to_vec()))
}

/// Orders certificates leaf → root by following issuer links. Falls back to input order
/// for anything that cannot be linked.
fn order_chain(certs: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let parsed: Vec<_> = certs
        .iter()
        .map(|d| parse_x509_certificate(d).ok().map(|(_, c)| c))
        .collect();
    if parsed.iter().any(Option::is_none) {
        return certs;
    }
    let parsed: Vec<_> = parsed.into_iter().flatten().collect();
    let issues_other = |i: usize| {
        parsed.iter().enumerate().any(|(j, other)| {
            j != i && other.issuer() == parsed[i].subject() && other.subject() != other.issuer()
        })
    };
    let Some(mut cur) = (0..parsed.len()).find(|&i| !issues_other(i)) else {
        return certs;
    };
    let mut order = vec![cur];
    loop {
        let next = (0..parsed.len())
            .find(|j| !order.contains(j) && parsed[*j].subject() == parsed[cur].issuer());
        let Some(next) = next else { break };
        order.push(next);
        cur = next;
    }
    // Append anything left over in original order.
    let rest: Vec<_> = (0..parsed.len()).filter(|i| !order.contains(i)).collect();
    order.extend(rest);
    order.into_iter().map(|i| certs[i].clone()).collect()
}
