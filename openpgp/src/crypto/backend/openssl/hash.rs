use crate::crypto::hash::Digest;
use crate::types::HashAlgorithm;
use crate::Result;

use ossl::digest::{DigestAlg, OsslDigest};

impl TryFrom<HashAlgorithm> for DigestAlg {
    type Error = crate::Error;
    fn try_from(a: HashAlgorithm) -> std::result::Result<Self, Self::Error> {
        match a {
            HashAlgorithm::SHA1 => Ok(DigestAlg::Sha1),
            HashAlgorithm::SHA256 => Ok(DigestAlg::Sha2_256),
            HashAlgorithm::SHA384 => Ok(DigestAlg::Sha2_384),
            HashAlgorithm::SHA512 => Ok(DigestAlg::Sha2_512),
            HashAlgorithm::SHA224 => Ok(DigestAlg::Sha2_224),
            HashAlgorithm::SHA3_256 => Ok(DigestAlg::Sha3_256),
            HashAlgorithm::SHA3_512 => Ok(DigestAlg::Sha3_512),
            HashAlgorithm::Private(_)
                | HashAlgorithm::Unknown (_)
                | HashAlgorithm::MD5
                | HashAlgorithm::RipeMD
                => Err(crate::Error::UnsupportedHashAlgorithm(a)),
        }
    }
}

struct OpenSslDigest {
    digest: OsslDigest,
    digest_size: usize,
    update_result: std::result::Result<(), ossl::Error>,
}

impl Clone for OpenSslDigest {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.try_clone()
                .expect("Sequoia requires clone to succeed"),
            digest_size: self.digest_size,
            update_result: self.update_result.clone(),
        }
    }
}

impl OpenSslDigest {
    fn new(algo: HashAlgorithm) -> Result<Self> {
        let ctx = super::context();

        Ok(Self {
            digest: OsslDigest::new(&ctx, algo.try_into()?, None)?,
            digest_size: algo.digest_size()?,
            update_result: Ok(()),
        })
    }
}

impl Digest for OpenSslDigest {
    fn update(&mut self, data: &[u8]) {
        if self.update_result.is_ok() {
            self.update_result = self.digest.update(data);
        }
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        self.update_result.clone()?;

        let mut buf = vec![0; self.digest_size];
        self.digest.finalize(&mut buf)?;

        let l = digest.len().min(buf.len());
        digest[..l].copy_from_slice(&buf[..l]);
        Ok(())
    }
}

impl std::io::Write for OpenSslDigest {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        // Do nothing.
        Ok(())
    }
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        // Try to construct a digest.  This indirectly looks up
        // digest's Nid and tries to initialize OpenSSL digest.  If
        // all of that succeeds the algorithm is supported by the
        // OpenSSL backend.
        OpenSslDigest::new(self).is_ok()
    }

    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: HashAlgorithm::is_supported()
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        Ok(Box::new(OpenSslDigest::new(self)?))
    }
}
