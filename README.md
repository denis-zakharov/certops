# certops

A small CLI to inspect and convert certificate keystores in **PEM**, **PKCS12** and **JKS** formats.
Pure Rust, no OpenSSL or Java required.

The input format is detected from the file content, not from its extension.

## Install

```sh
cargo install --path .                                       # from a checkout
cargo install --git https://github.com/denis-zakharov/certops # straight from GitHub
```

## Usage

### `text` — show certificates

```sh
certops text keystore.p12                  # subject, issuer, validity, SANs
certops text keystore.p12 --full           # + serial, algorithms, key size, SHA-256, extensions
certops text keystore.jks --password secret
```

`--password` is only needed for PKCS12 and JKS; if omitted you are asked interactively.

### `export` — convert between formats

```sh
certops export keystore.p12 out            # PKCS12 -> PEM files
certops export out.pem keystore.p12 --key out.key.pem
certops export keystore.p12 keystore.jks   # PKCS12 -> JKS
```

Converting **to PEM** writes several files, with `<output>` as a prefix (`out` and `out.pem` are equivalent):

| File | Content |
|------|---------|
| `<output>.pem` | everything: private key, chain and trusted certificates |
| `<output>.cl.pem` | certificate chain (leaf first) |
| `<output>.ca.pem` | trusted (standalone CA) certificates, only if any |
| `<output>.key.pem` | private key (PKCS#8, encrypted unless `--noenc`), created with mode `0600` |

Converting **to PKCS12 or JKS** writes `<output>` as is. The target format comes from `--to pem|p12|jks`;
without it, from the output extension (`.jks`, `.p12`/`.pfx`); otherwise PEM input becomes PKCS12 and
everything else becomes PEM.

| Option | Meaning |
|--------|---------|
| `--password` | password to read the input and, by default, to protect the output (asked interactively if omitted) |
| `--out-password` | separate password for a PKCS12/JKS output |
| `--noenc` | PEM output: write the private key unencrypted (default: encrypted with the output password) |
| `--key FILE` | PEM input only: file with the private key, e.g. `out.key.pem` |
| `--ca FILE` | PEM input only: file with trusted certificates, e.g. `out.ca.pem` |

## Model and limits

A keystore is treated as **one private key + its certificate chain + any number of trusted CA certificates**.

- A file with more than one private key is rejected.
- Aliases are not preserved; generated ones are used (`key`, `ca-1`, ...).
- PEM keys must be PKCS#8: plain (`BEGIN PRIVATE KEY`) or encrypted (`BEGIN ENCRYPTED PRIVATE KEY`, PBES2).
  The password is asked when needed. For `RSA PRIVATE KEY` / `EC PRIVATE KEY` run
  `openssl pkcs8 -topk8 -nocrypt`.
- JKS uses the store password as the key password (the `keytool` default). JCEKS is not supported.
- Without a private key, PEM certificates are treated as trusted certificates.

## Development

```sh
make help       # list targets
make all        # fmt-check, lint, test, build
make test-p12   # generate test.p12 (password: changeit) for manual testing; needs openssl
```

`test.p12` is git-ignored. Try it with:

```sh
cargo run -- text test.p12 --password changeit --full
```
