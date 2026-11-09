use crate::wordlist;
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

const BITS_IN_ONE_BYTE: usize = 8;
const BITS_PER_ONE_WORD: usize = 11;
const WORD_MASK: usize = (1 << BITS_PER_ONE_WORD) - 1;
const MAX_ENTROPY_BYTES: usize = 32;
const MAX_WORDS: usize = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MnemonicStrength {
    Bits128,
    Bits160,
    Bits192,
    Bits224,
    Bits256,
}

impl MnemonicStrength {
    pub const fn as_bytes(&self) -> usize {
        match self {
            Self::Bits128 => 16,
            Self::Bits160 => 20,
            Self::Bits192 => 24,
            Self::Bits224 => 28,
            Self::Bits256 => 32,
        }
    }

    pub const fn as_bits(&self) -> usize {
        self.as_bytes() * BITS_IN_ONE_BYTE
    }

    pub const fn checksum(&self) -> usize {
        self.as_bits() / 32
    }

    pub const fn words(&self) -> usize {
        (self.as_bits() + self.checksum()) / BITS_PER_ONE_WORD
    }
}

#[derive(Debug)]
pub enum MnemonicError {
    Rng(getrandom::Error),
}

impl From<getrandom::Error> for MnemonicError {
    fn from(e: getrandom::Error) -> Self {
        Self::Rng(e)
    }
}

pub struct Mnemonic {
    indices: [u16; MAX_WORDS],
    strength: MnemonicStrength,
}

impl Mnemonic {
    pub fn generate(strength: MnemonicStrength) -> Result<Self, MnemonicError> {
        let mut buf = Zeroizing::new([0u8; MAX_ENTROPY_BYTES]);
        getrandom::fill(&mut buf[..strength.as_bytes()])?;

        Ok(Self::encode(&buf, strength))
    }

    fn encode(buf: &[u8; MAX_ENTROPY_BYTES], strength: MnemonicStrength) -> Self {
        let bytes = &buf[..strength.as_bytes()];
        let cs_bits = strength.checksum();

        let hash = Sha256::digest(bytes);
        let checksum = (hash[0] >> (BITS_IN_ONE_BYTE - cs_bits)) as usize;

        let mut acc: usize = 0;
        let mut occupied_bits: usize = 0;
        let mut indices = [0u16; MAX_WORDS];
        let mut idx = 0;

        for &byte in bytes {
            acc = (acc << BITS_IN_ONE_BYTE) | byte as usize;
            occupied_bits += BITS_IN_ONE_BYTE;

            if occupied_bits >= BITS_PER_ONE_WORD {
                occupied_bits -= BITS_PER_ONE_WORD;
                indices[idx] = ((acc >> occupied_bits) & WORD_MASK) as u16;
                idx += 1;
            }
        }

        indices[idx] = (((acc << cs_bits) | checksum) & WORD_MASK) as u16;

        Self { indices, strength }
    }

    pub fn strength(&self) -> MnemonicStrength {
        self.strength
    }

    pub fn indices(&self) -> &[u16] {
        &self.indices[..self.strength.words()]
    }

    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.indices()
            .iter()
            .map(|&i| wordlist::WORDLIST[i as usize])
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut words = self.words();
        if let Some(first) = words.next() {
            f.write_str(first)?;
            for w in words {
                f.write_str(" ")?;
                f.write_str(w)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [MnemonicStrength; 5] = [
        MnemonicStrength::Bits128,
        MnemonicStrength::Bits160,
        MnemonicStrength::Bits192,
        MnemonicStrength::Bits224,
        MnemonicStrength::Bits256,
    ];

    fn strength_for(len: usize) -> MnemonicStrength {
        *ALL.iter()
            .find(|s| s.as_bytes() == len)
            .expect("bad entropy length")
    }

    fn from_entropy(entropy: &[u8]) -> Mnemonic {
        let mut buf = [0u8; MAX_ENTROPY_BYTES];
        buf[..entropy.len()].copy_from_slice(entropy);
        Mnemonic::encode(&buf, strength_for(entropy.len()))
    }

    fn rep(word: &str, n: usize, last: &str) -> String {
        let mut v = vec![word; n];
        v.push(last);
        v.join(" ")
    }

    /// 1. Официальные векторы BIP39 (trezor/python-mnemonic, vectors.json)
    #[test]
    fn official_vectors() {
        let vectors: Vec<(Vec<u8>, String)> = vec![
            (vec![0x00; 16], rep("abandon", 11, "about")),
            (
                vec![0x7f; 16],
                "legal winner thank year wave sausage worth useful legal winner thank yellow"
                    .into(),
            ),
            (
                vec![0x80; 16],
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage above"
                    .into(),
            ),
            (vec![0xff; 16], rep("zoo", 11, "wrong")),
            (vec![0x00; 24], rep("abandon", 17, "agent")),
            (vec![0xff; 24], rep("zoo", 17, "when")),
            (vec![0x00; 32], rep("abandon", 23, "art")),
            (vec![0xff; 32], rep("zoo", 23, "vote")),
            (
                hex::decode("9e885d952ad362caeb4efe34a8e91bd2").unwrap(),
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
                    .into(),
            ),
        ];
        for (entropy, expected) in vectors {
            assert_eq!(
                from_entropy(&entropy).to_string(),
                expected,
                "entropy {}",
                hex::encode(&entropy)
            );
        }
    }

    /// 2. Сверка с эталонной реализацией на случайной энтропии, все 5 длин
    ///    (в официальных векторах нет 160 и 224 бит, этот тест их покрывает)
    #[test]
    fn matches_reference_implementation() {
        for strength in ALL {
            for _ in 0..10_000 {
                let mut e = vec![0u8; strength.as_bytes()];
                getrandom::fill(&mut e).unwrap();
                let ours = from_entropy(&e).to_string();
                let reference = bip39::Mnemonic::from_entropy(&e).unwrap().to_string();
                assert_eq!(ours, reference, "entropy {}", hex::encode(&e));
            }
        }
    }

    /// 3. Реальный путь через generate(): независимый парсер принимает фразу
    #[test]
    fn generated_mnemonics_are_valid() {
        for strength in ALL {
            for _ in 0..1_000 {
                let m = Mnemonic::generate(strength).unwrap();
                assert_eq!(m.words().count(), strength.words());
                bip39::Mnemonic::parse_normalized(&m.to_string())
                    .expect("эталонный парсер отверг фразу (checksum или слово)");
            }
        }
    }

    /// 4. Словарь совпадает с официальным английским
    #[test]
    fn wordlist_matches_bip39() {
        let reference = bip39::Language::English.word_list();
        assert_eq!(&wordlist::WORDLIST[..], &reference[..]);
    }

    #[test]
    fn word_counts() {
        let counts: Vec<_> = ALL.iter().map(|s| s.words()).collect();
        assert_eq!(counts, [12, 15, 18, 21, 24]);
    }
}
