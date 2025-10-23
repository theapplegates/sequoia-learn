# SLH-DSA CipherSuite Implementation - Completion Report

## Summary

✅ **Successfully added SLH-DSA cipher suite support to Sequoia-PGP**

All three SLH-DSA variants are now available as CipherSuite options, enabling key generation through the `CertBuilder` API.

## Changes Made

### 1. CipherSuite Enum (openpgp/src/cert/builder.rs)

Added three new variants to the `CipherSuite` enum:

```rust
/// SLH-DSA-SHAKE-128s signature algorithm (stateless hash-based,
/// small variant).
SLHDSA128s,

/// SLH-DSA-SHAKE-128f signature algorithm (stateless hash-based,
/// fast variant).
SLHDSA128f,

/// SLH-DSA-SHAKE-256s signature algorithm (stateless hash-based,
/// 256-bit security).
SLHDSA256s,
```

**Lines**: 91-101

### 2. CipherSuite::variants() Method

Updated the variants iterator to include SLH-DSA:

```rust
[ Cv25519, RSA3k, P256, P384, P521, RSA2k, RSA4k, MLDSA65, MLDSA87,
  SLHDSA128s, SLHDSA128f, SLHDSA256s ]
```

**Lines**: 119-120

### 3. CipherSuite::is_supported() Method

Added algorithm support checks:

```rust
SLHDSA128s => {
    check_pk!(PublicKeyAlgorithm::SLHDSA128s);
},
SLHDSA128f => {
    check_pk!(PublicKeyAlgorithm::SLHDSA128f);
},
SLHDSA256s => {
    check_pk!(PublicKeyAlgorithm::SLHDSA256s);
},
```

**Lines**: 182-190

### 4. generate_v4_key() Method

Added error case (SLH-DSA requires v6 keys):

```rust
CipherSuite::MLDSA65 | CipherSuite::MLDSA87 |
CipherSuite::SLHDSA128s | CipherSuite::SLHDSA128f |
CipherSuite::SLHDSA256s =>
    Err(Error::InvalidOperation(
        "can't use algorithms for v4 keys".into())
        .into()),
```

**Lines**: 253-258

### 5. generate_v6_key() Method

Added key generation logic for SLH-DSA:

```rust
a @ CipherSuite::SLHDSA128s | a @ CipherSuite::SLHDSA128f |
a @ CipherSuite::SLHDSA256s =>
    match (sign, encrypt, a) {
        (true, false, CipherSuite::SLHDSA128s) =>
            Key6::generate_slhdsa128s(),
        (true, false, CipherSuite::SLHDSA128f) =>
            Key6::generate_slhdsa128f(),
        (true, false, CipherSuite::SLHDSA256s) =>
            Key6::generate_slhdsa256s(),
        (true, false, _) => unreachable!(),
        (false, true, _) =>
            Err(Error::InvalidOperation(
                "SLH-DSA algorithms are signature-only and cannot be used for encryption".into())
                .into()),
        (true, true, _) =>
            Err(Error::InvalidOperation(
                "Can't use key for encryption and signing".into())
                .into()),
        (false, false, _) =>
            Err(Error::InvalidOperation(
                "No key flags set".into())
                .into()),
    },
```

**Lines**: 344-366

**Important**: SLH-DSA is signature-only, so it returns an error when encryption flags are set.

### 6. Test Fix: all_ciphersuites()

Updated the test to handle signature-only algorithms:

```rust
#[test]
fn all_ciphersuites() {
    use CipherSuite::*;

    for cs in CipherSuite::variants()
        .into_iter().filter(|cs| cs.is_supported().is_ok())
    {
        // SLH-DSA algorithms are signature-only, so we need to
        // create signing keys instead of encryption keys for them.
        let builder = CertBuilder::new()
            .set_profile(crate::Profile::RFC9580).unwrap()
            .set_cipher_suite(cs);

        match cs {
            SLHDSA128s | SLHDSA128f | SLHDSA256s => {
                builder.add_signing_subkey()
                    .generate()
                    .unwrap();
            },
            _ => {
                builder.add_transport_encryption_subkey()
                    .generate()
                    .unwrap();
            }
        }
    }
}
```

**Lines**: 2025-2051

## Test Results

### All PQC Tests Pass ✅

```
running 10 tests
test parse::stream::test::detached_slhdsa_256s ... ok
test parse::stream::test::detached_slhdsa_128f ... ok
test parse::stream::test::detached_mldsa_65 ... ok
test parse::stream::test::detached_mldsa_87 ... ok
test cert::test::mldsa65_ed25519 ... ok
test parse::stream::test::detached_slhdsa_128s ... ok
test cert::test::slhdsa256s_mlkem768_x25519 ... ok
test cert::test::mldsa87_ed448 ... ok
test cert::test::slhdsa128s_mlkem768_x25519 ... ok
test cert::test::slhdsa128f_mlkem768_x25519 ... ok

test result: ok. 10 passed; 0 failed
```

### All Builder Tests Pass ✅

```
running 16 tests
test cert::builder::tests::all_ciphersuites ... ok
test cert::builder::tests::defaults ... ok
test cert::builder::tests::builder_roundtrip ... ok
... (all 16 tests passed)

test result: ok. 16 passed; 0 failed
```

### Example Program Works ✅

Created `openpgp/examples/slhdsa_keygen.rs` which successfully generates keys for all three variants:

```
Testing SLH-DSA key generation with CipherSuite...

Generating SLHDSA256s key...
✓ SLHDSA256s key generated successfully
  Primary key algorithm: SLHDSA256s

Generating SLHDSA128s key...
✓ SLHDSA128s key generated successfully
  Primary key algorithm: SLHDSA128s

Generating SLHDSA128f key...
✓ SLHDSA128f key generated successfully
  Primary key algorithm: SLHDSA128f

✅ All SLH-DSA CipherSuite tests passed!
```

## Usage Examples

### Generating SLH-DSA Keys

```rust
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::Profile;

// Generate SLHDSA256s key
let (cert, _) = CertBuilder::new()
    .set_profile(Profile::RFC9580)?
    .set_cipher_suite(CipherSuite::SLHDSA256s)
    .generate()?;

// Generate SLHDSA128s key
let (cert, _) = CertBuilder::new()
    .set_profile(Profile::RFC9580)?
    .set_cipher_suite(CipherSuite::SLHDSA128s)
    .generate()?;

// Generate SLHDSA128f key
let (cert, _) = CertBuilder::new()
    .set_profile(Profile::RFC9580)?
    .set_cipher_suite(CipherSuite::SLHDSA128f)
    .generate()?;
```

### Adding Signing Subkeys

```rust
// SLH-DSA is signature-only, so use signing subkeys
let (cert, _) = CertBuilder::new()
    .set_profile(Profile::RFC9580)?
    .set_cipher_suite(CipherSuite::SLHDSA256s)
    .add_signing_subkey()
    .generate()?;
```

## Important Notes

### Algorithm Properties

1. **Signature-only**: SLH-DSA algorithms cannot be used for encryption
2. **V6 keys only**: SLH-DSA requires OpenPGP v6 (RFC 9580)
3. **Backend requirement**: OpenSSL backend (`crypto-openssl`) is required

### Key Sizes

| Variant | Public Key | Secret Key | Signature |
|---------|-----------|-----------|-----------|
| SLHDSA128s | 32 bytes | 64 bytes | 7,856 bytes |
| SLHDSA128f | 32 bytes | 64 bytes | 17,088 bytes |
| SLHDSA256s | 64 bytes | 128 bytes | 29,792 bytes |

### Standards Compliance

- **RFC 9580**: OpenPGP v6
- **draft-ietf-openpgp-pqc-13**: Post-Quantum Cryptography in OpenPGP (October 14, 2025)
- **NIST FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signatures)
- **Algorithm IDs**: 32 (SLHDSA128s), 33 (SLHDSA128f), 34 (SLHDSA256s)

## Environment Requirements

### Critical Build Requirements ✅

Both environment variables are correctly set:

```bash
export BINDGEN_EXTRA_CLANG_ARGS="-I/opt/homebrew/opt/openssl@3/include"
export RUSTFLAGS="-L/opt/homebrew/opt/openssl@3/lib"
```

Without these, the build will fail:
- Missing `BINDGEN_EXTRA_CLANG_ARGS`: bindgen fails to find `openssl/core_dispatch.h`
- Missing `RUSTFLAGS`: linker fails with "library 'crypto' not found"

### OpenSSL Configuration

```bash
export OPENSSL_DIR=/opt/homebrew/opt/openssl@3
export OPENSSL_LIB_DIR=/opt/homebrew/opt/openssl@3/lib
export OPENSSL_INCLUDE_DIR=/opt/homebrew/opt/openssl@3/include
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig
```

## Build Commands

```bash
# Build library
cargo build -p sequoia-openpgp --no-default-features --features crypto-openssl,compression

# Run all PQC tests
cargo test -p sequoia-openpgp --no-default-features --features crypto-openssl,compression --lib -- mldsa slhdsa

# Run example
cargo run -p sequoia-openpgp --example slhdsa_keygen --no-default-features --features crypto-openssl,compression
```

## Files Modified

1. **openpgp/src/cert/builder.rs** - Main changes (6 sections modified)
2. **openpgp/examples/slhdsa_keygen.rs** - New example file (created)

## Integration Status

### ✅ Completed

- [x] CipherSuite enum variants added
- [x] variants() iterator updated
- [x] is_supported() checks implemented
- [x] generate_v4_key() error handling
- [x] generate_v6_key() key generation
- [x] Test fixes (all_ciphersuites)
- [x] All library tests passing
- [x] Example program working
- [x] Documentation complete

### 🔍 Next Steps (Optional)

The library implementation is complete. The `sq` CLI tool is in a separate repository and would need similar updates to expose these cipher suites via command-line flags.

To use SLH-DSA in applications:
1. Use the `CertBuilder` API with the new cipher suite variants
2. Ensure OpenSSL backend is enabled
3. Use RFC 9580 profile for v6 keys

## Conclusion

✅ **SLH-DSA cipher suite support is fully implemented and tested**

All three SLH-DSA variants (SLHDSA128s, SLHDSA128f, SLHDSA256s) are now available through the `CipherSuite` enum and work correctly with the `CertBuilder` API.

---

**Date**: 2025-10-21  
**Branch**: `justus/pqc-ossl`  
**Backend**: OpenSSL via `ossl` crate from kryoptic  
**Draft Standard**: draft-ietf-openpgp-pqc-13
