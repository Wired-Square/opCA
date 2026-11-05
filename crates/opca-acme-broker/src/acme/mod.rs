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

mod issue;
mod problem;
pub mod store;

pub use issue::{Issuer, check_identifier};
pub use problem::{Problem, ProblemType};
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

#[cfg(test)]
mod tests {
    use super::base64url;

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
        }
    }
}
