use core::fmt;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// OS number generator is unavailable or returned an error
    RandomUnavailable,
    /// Invalid number of bytes provided
    InvalidLength { expected: usize, received: usize },
}

pub struct Entropy<const N: usize>([u8; N]);

impl<const N: usize> Entropy<N> {
    pub fn generate() -> Result<Self, EntropyError> {
        let mut secret = Self([0u8; N]);

        getrandom::fill(&mut secret.0).map_err(|_| EntropyError::RandomUnavailable)?;

        Ok(secret)
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> ZeroizeOnDrop for Entropy<N> {}

impl<const N: usize> fmt::Debug for Entropy<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{}>", N)
    }
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RandomUnavailable => f.write_str("OS number generator is unavailable"),
            Self::InvalidLength { expected, received } => {
                write!(f, "expected {expected} bytes, received {received}")
            }
        }
    }
}

impl core::error::Error for EntropyError {}
