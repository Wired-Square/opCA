//! The broker's own ACME server (RFC 8555): what it records, how it issues, and how it validates.

/// An enum spelt as fixed text, with `as_str` and `parse` for each way across.
macro_rules! named {
    ($(#[$meta:meta])* pub enum $name:ident { $($variant:ident = $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            pub fn parse(text: &str) -> Option<Self> {
                match text {
                    $($text => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl $crate::acme::Named for $name {
            fn as_str(self) -> &'static str {
                Self::as_str(self)
            }

            fn parse(text: &str) -> Option<Self> {
                Self::parse(text)
            }
        }
    };
}

trait Named: Copy {
    fn as_str(self) -> &'static str;
    fn parse(text: &str) -> Option<Self>;
}

pub(crate) mod issue;
pub(crate) mod listener;
mod problem;
pub mod request;
pub(crate) mod server;
pub mod store;
pub mod validate;

pub use issue::{Issuer, check_identifier};
pub use problem::{Problem, ProblemType};
pub use server::ORDER_LIFETIME;
pub use store::Store;

/// Base64url without padding (RFC 4648 §5), as ACME writes tokens and digests.
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(
                ALPHABET[(triple >> (18 - 6 * i) & 0x3f) as usize],
            ));
        }
    }
    out
}

/// The inverse of [`base64url`]: `None` for padding, any other alphabet, or stray trailing bits.
pub fn from_base64url(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0);
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6 | u32::from(value)) & 0xffff;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    (bits < 6 && buffer & ((1 << bits) - 1) == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::{base64url, from_base64url};

    #[test]
    fn base64url_matches_rfc_4648_without_padding() {
        let cases: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (&[0xfb, 0xff, 0xbf], "-_-_"),
        ];
        for (bytes, encoded) in cases {
            assert_eq!(base64url(bytes), encoded);
            assert_eq!(from_base64url(encoded).as_deref(), Some(bytes));
        }
    }

    #[test]
    fn from_base64url_refuses_what_base64url_never_writes() {
        for text in ["Z", "Zh", "Zm9=", "Zm+v", "Zm/v", "Zm9v YQ"] {
            assert_eq!(from_base64url(text), None, "{text}");
        }
    }
}
