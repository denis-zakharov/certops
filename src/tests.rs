use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

use crate::bundle::{Bundle, Format, certs_to_pem, detect_format, key_to_pem};
use crate::{text, write_pem_files};

/// Returns (leaf DER, CA DER, leaf key PKCS#8 DER).
fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().unwrap();
    let mut params =
        CertificateParams::new(vec!["example.com".into(), "*.example.com".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "leaf.example.com");
    let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
    (
        leaf.der().to_vec(),
        ca.der().to_vec(),
        leaf_key.serialize_der(),
    )
}

#[test]
fn pkcs12_roundtrip() {
    let (leaf, ca, key) = fixture();
    let b = Bundle {
        key: Some(key.clone()),
        chain: vec![leaf.clone(), ca.clone()],
        trusted: vec![ca.clone()],
    };
    let p12 = b.to_pkcs12("secret").unwrap();
    assert_eq!(detect_format(&p12), Format::Pkcs12);

    let back = Bundle::from_pkcs12(&p12, "secret").unwrap();
    assert_eq!(back.key, Some(key));
    assert_eq!(back.chain, vec![leaf, ca.clone()]);
    assert_eq!(back.trusted, vec![ca]);
    assert!(Bundle::from_pkcs12(&p12, "wrong").is_err());
}

#[test]
fn pem_orders_chain_and_roundtrips() {
    let (leaf, ca, key) = fixture();
    // CA deliberately first: the chain must be re-ordered leaf -> root.
    let pem = format!("{}{}", key_to_pem(&key), certs_to_pem([&ca, &leaf]));
    assert_eq!(detect_format(pem.as_bytes()), Format::Pem);
    let b = Bundle::from_pem(pem.as_bytes()).unwrap();
    assert_eq!(b.chain, vec![leaf, ca]);
    assert_eq!(b.key, Some(key));
}

#[test]
fn pem_without_key_is_trust_store() {
    let (leaf, ca, _) = fixture();
    let b = Bundle::from_pem(certs_to_pem([&leaf, &ca]).as_bytes()).unwrap();
    assert!(b.key.is_none() && b.chain.is_empty());
    assert_eq!(b.trusted.len(), 2);
    // and it survives a PKCS12 round trip
    let back = Bundle::from_pkcs12(&b.to_pkcs12("").unwrap(), "").unwrap();
    assert_eq!(back.trusted.len(), 2);
}

#[test]
fn legacy_key_formats_rejected() {
    let pem = pem::encode(&pem::Pem::new("RSA PRIVATE KEY", vec![1, 2, 3]));
    assert!(Bundle::from_pem(pem.as_bytes()).is_err());
}

#[test]
fn text_short_and_full() {
    let (leaf, ca, key) = fixture();
    let b = Bundle {
        key: Some(key),
        chain: vec![leaf, ca],
        trusted: vec![],
    };
    let short = text::render(&b, false).unwrap();
    assert!(short.contains("CN=leaf.example.com"));
    assert!(short.contains("CN=Test CA"));
    assert!(short.contains("DNS:example.com, DNS:*.example.com"));
    assert!(!short.contains("SHA-256"));

    let full = text::render(&b, true).unwrap();
    assert!(full.contains("SHA-256"));
    assert!(full.contains("Basic Constraints"));
    assert!(full.contains("Public key"));
}

#[test]
fn export_writes_expected_files() {
    let (leaf, ca, key) = fixture();
    let b = Bundle {
        key: Some(key),
        chain: vec![leaf, ca.clone()],
        trusted: vec![ca],
    };
    let dir = tempfile::tempdir().unwrap();
    write_pem_files(&b, &dir.path().join("out.pem")).unwrap();
    for f in ["out.pem", "out.cl.pem", "out.ca.pem", "out.key.pem"] {
        assert!(dir.path().join(f).exists(), "{f} missing");
    }
    let all = Bundle::from_pem(&std::fs::read(dir.path().join("out.pem")).unwrap()).unwrap();
    // key + chain (2) + trusted (1) all land in the combined file
    assert!(all.key.is_some());
    assert_eq!(all.chain.len(), 3);
}

#[test]
fn jks_roundtrip() {
    let (leaf, ca, key) = fixture();
    let b = Bundle {
        key: Some(key.clone()),
        chain: vec![leaf.clone(), ca.clone()],
        trusted: vec![ca.clone()],
    };
    let jks = b.to_jks("secret").unwrap();
    assert_eq!(detect_format(&jks), Format::Jks);

    let back = Bundle::from_jks(&jks, "secret").unwrap();
    assert_eq!(back.key, Some(key));
    assert_eq!(back.chain, vec![leaf, ca.clone()]);
    assert_eq!(back.trusted, vec![ca]);
    assert!(Bundle::from_jks(&jks, "wrong").is_err());

    let mut tampered = jks.clone();
    tampered[20] ^= 1;
    assert!(Bundle::from_jks(&tampered, "secret").is_err());
}

#[test]
fn jks_without_key_keeps_all_certs_as_trusted() {
    let (leaf, ca, _) = fixture();
    let b = Bundle {
        key: None,
        chain: vec![],
        trusted: vec![leaf, ca],
    };
    let back = Bundle::from_jks(&b.to_jks("").unwrap(), "").unwrap();
    assert!(back.key.is_none());
    assert_eq!(back.trusted.len(), 2);
}

#[test]
fn jks_pkcs12_conversion() {
    let (leaf, ca, key) = fixture();
    let b = Bundle {
        key: Some(key),
        chain: vec![leaf, ca],
        trusted: vec![],
    };
    let via = Bundle::from_pkcs12(&b.to_pkcs12("a").unwrap(), "a").unwrap();
    let back = Bundle::from_jks(&via.to_jks("b").unwrap(), "b").unwrap();
    assert_eq!((back.key, back.chain), (b.key, b.chain));
}
