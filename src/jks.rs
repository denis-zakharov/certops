//! Reader and writer for the Java KeyStore (JKS) format.
//!
//! Layout: magic `FEEDFEED`, version, entry count, entries, then a SHA-1 trailer computed over
//! `UTF-16BE(password) || "Mighty Aphrodite" || everything before the trailer`.
//! Private keys are PKCS#8 wrapped with Sun's proprietary XOR-keystream scheme.

use anyhow::{Result, anyhow, bail, ensure};
use sha1::{Digest, Sha1};

pub const MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];
const WHITENER: &[u8] = b"Mighty Aphrodite";
const KEY_PROTECTOR_OID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01];
const SALT_LEN: usize = 20;
const DIGEST_LEN: usize = 20;
const TAG_KEY: u32 = 1;
const TAG_CERT: u32 = 2;

/// Entries of a JKS file, as DER blobs.
#[derive(Debug, Default)]
pub struct Jks {
    /// Plain PKCS#8 key and its chain (leaf first), if the store has a key entry.
    pub key: Option<(Vec<u8>, Vec<Vec<u8>>)>,
    /// Trusted certificate entries.
    pub trusted: Vec<Vec<u8>>,
}

fn password_bytes(password: &str) -> Vec<u8> {
    password.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn integrity_digest(password: &str, body: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha1::new();
    h.update(password_bytes(password));
    h.update(WHITENER);
    h.update(body);
    h.finalize().into()
}

/// XORs `data` with the keystream derived from the salt; the operation is its own inverse.
fn xor_keystream(password: &[u8], salt: &[u8], data: &[u8]) -> Vec<u8> {
    let mut digest = salt.to_vec();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(DIGEST_LEN) {
        digest = Sha1::new()
            .chain_update(password)
            .chain_update(&digest)
            .finalize()
            .to_vec();
        out.extend(chunk.iter().zip(&digest).map(|(a, b)| a ^ b));
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.0.len() >= n, "truncated JKS file");
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into()?))
    }
    fn utf(&mut self) -> Result<String> {
        let n = self.u16()? as usize;
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn blob(&mut self) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn cert(&mut self) -> Result<Vec<u8>> {
        let kind = self.utf()?;
        ensure!(kind == "X.509", "unsupported certificate type {kind:?}");
        Ok(self.blob()?.to_vec())
    }
}

pub fn parse(data: &[u8], password: &str) -> Result<Jks> {
    ensure!(
        data.len() >= 12 + DIGEST_LEN && data[..4] == MAGIC,
        "not a JKS file"
    );
    let (body, trailer) = data.split_at(data.len() - DIGEST_LEN);
    ensure!(
        integrity_digest(password, body) == trailer,
        "cannot read JKS (wrong password or corrupt file?): integrity check failed"
    );

    let mut r = Reader(&body[4..]);
    let version = r.u32()?;
    ensure!(
        version == 1 || version == 2,
        "unsupported JKS version {version}"
    );
    let count = r.u32()?;
    let mut jks = Jks::default();
    for _ in 0..count {
        let tag = r.u32()?;
        let alias = r.utf()?;
        r.take(8)?; // creation timestamp
        match tag {
            TAG_KEY => {
                let key = decrypt_key(r.blob()?, password)?;
                let n = r.u32()?;
                let chain = (0..n).map(|_| r.cert()).collect::<Result<Vec<_>>>()?;
                if jks.key.is_some() {
                    bail!(
                        "JKS contains more than one private key entry (second: {alias:?}); only one is supported"
                    );
                }
                jks.key = Some((key, chain));
            }
            TAG_CERT => jks.trusted.push(r.cert()?),
            _ => bail!("unknown JKS entry type {tag}"),
        }
    }
    Ok(jks)
}

pub fn write(jks: &Jks, password: &str) -> Result<Vec<u8>> {
    let mut out = MAGIC.to_vec();
    out.extend(2u32.to_be_bytes());
    let count = jks.key.is_some() as u32 + jks.trusted.len() as u32;
    out.extend(count.to_be_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as u64;

    let utf = |out: &mut Vec<u8>, s: &str| {
        out.extend((s.len() as u16).to_be_bytes());
        out.extend(s.as_bytes());
    };
    let blob = |out: &mut Vec<u8>, b: &[u8]| {
        out.extend((b.len() as u32).to_be_bytes());
        out.extend(b);
    };

    if let Some((key, chain)) = &jks.key {
        out.extend(TAG_KEY.to_be_bytes());
        utf(&mut out, "key");
        out.extend(now.to_be_bytes());
        blob(&mut out, &encrypt_key(key, password));
        out.extend((chain.len() as u32).to_be_bytes());
        for c in chain {
            utf(&mut out, "X.509");
            blob(&mut out, c);
        }
    }
    for (i, c) in jks.trusted.iter().enumerate() {
        out.extend(TAG_CERT.to_be_bytes());
        utf(&mut out, &format!("ca-{}", i + 1));
        out.extend(now.to_be_bytes());
        utf(&mut out, "X.509");
        blob(&mut out, c);
    }
    let digest = integrity_digest(password, &out);
    out.extend(digest);
    Ok(out)
}

// --- Sun key protector -------------------------------------------------------------------

fn der_len(n: usize) -> Vec<u8> {
    match n {
        0..=127 => vec![n as u8],
        128..=255 => vec![0x81, n as u8],
        _ => vec![0x82, (n >> 8) as u8, n as u8],
    }
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(der_len(content.len()));
    v.extend(content);
    v
}

/// Reads one TLV, returning (tag, content, rest).
fn der_read(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let bad = || anyhow!("malformed EncryptedPrivateKeyInfo");
    let (&tag, rest) = data.split_first().ok_or_else(bad)?;
    let (&first, rest) = rest.split_first().ok_or_else(bad)?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        ensure!(
            n > 0 && n <= 4 && rest.len() >= n,
            "malformed EncryptedPrivateKeyInfo"
        );
        (
            rest[..n].iter().fold(0usize, |a, b| a << 8 | *b as usize),
            &rest[n..],
        )
    };
    ensure!(rest.len() >= len, "malformed EncryptedPrivateKeyInfo");
    Ok((tag, &rest[..len], &rest[len..]))
}

fn encrypt_key(pkcs8: &[u8], password: &str) -> Vec<u8> {
    let pw = password_bytes(password);
    let salt: [u8; SALT_LEN] = rand::random();
    let mut payload = salt.to_vec();
    payload.extend(xor_keystream(&pw, &salt, pkcs8));
    payload.extend(Sha1::new().chain_update(&pw).chain_update(pkcs8).finalize());

    let mut alg = der(0x06, &KEY_PROTECTOR_OID);
    alg.extend([0x05, 0x00]);
    let mut info = der(0x30, &alg);
    info.extend(der(0x04, &payload));
    der(0x30, &info)
}

fn decrypt_key(encrypted_info: &[u8], password: &str) -> Result<Vec<u8>> {
    let (tag, info, _) = der_read(encrypted_info)?;
    ensure!(tag == 0x30, "malformed EncryptedPrivateKeyInfo");
    let (_, alg, rest) = der_read(info)?;
    let (_, oid, _) = der_read(alg)?;
    ensure!(
        oid == KEY_PROTECTOR_OID,
        "unsupported JKS key protection algorithm (JCEKS?)"
    );
    let (_, payload, _) = der_read(rest)?;
    ensure!(
        payload.len() >= SALT_LEN + DIGEST_LEN,
        "malformed protected key"
    );

    let pw = password_bytes(password);
    let (salt, rest) = payload.split_at(SALT_LEN);
    let (enc, check) = rest.split_at(rest.len() - DIGEST_LEN);
    let plain = xor_keystream(&pw, salt, enc);
    ensure!(
        Sha1::new()
            .chain_update(&pw)
            .chain_update(&plain)
            .finalize()
            .as_slice()
            == check,
        "private key password mismatch (key and store passwords must be equal)"
    );
    Ok(plain)
}
