//! A request's flattened JWS checked as RFC 8555 §6 has it: its url, its
//! nonce, the key or account it names, and its signature.

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::crypto::CryptoProvider;
use wslib_crypto_jose::{
    Error as JoseError, ErrorKind, FlattenedJws, Jwk, KeyRef, ProtectedHeader,
};

use super::store::{Account, AccountStatus, Store};
use super::{Problem, ProblemType, base64url};

/// How a request must name its key: new-account by `jwk`, an account's requests by `kid`, revoke-cert by either.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyRule {
    Jwk,
    Kid,
    Either,
}

#[derive(Clone, Debug)]
pub enum Signer {
    Account { account: Account, key: Jwk },
    Key(Jwk),
}

impl Signer {
    pub fn key(&self) -> &Jwk {
        match self {
            Self::Account { key, .. } | Self::Key(key) => key,
        }
    }
}

#[derive(Debug)]
pub struct Verified {
    pub signer: Signer,
    pub header: ProtectedHeader,
    /// Empty for a POST-as-GET.
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub struct KeyChange {
    pub account: Account,
    /// Not yet checked against other accounts' keys; one that is in use is the caller's `409 Conflict`.
    pub new_key: Jwk,
}

pub struct Requests<'a> {
    pub nonces: &'a Nonces,
    pub store: &'a Store,
    pub provider: &'a CryptoProvider,
    /// An account's URL is this followed by its id.
    pub accounts_url: &'a str,
}

impl Requests<'_> {
    pub fn account_url(&self, id: i64) -> String {
        format!("{}{id}", self.accounts_url)
    }

    /// Checks `body` was signed for `url` with a fresh nonce by the key `rule` asks for, and redeems the nonce.
    pub async fn verify(&self, body: &[u8], url: &str, rule: KeyRule) -> Result<Verified, Problem> {
        let (jws, signer) = self.verified(body, url, rule).await?;
        let (header, payload) = jws.into_parts();
        Ok(Verified {
            signer,
            header,
            payload,
        })
    }

    /// RFC 8555 §7.3.5, the inner JWS checked by the crate; here, that it names the `kid`'s account.
    pub async fn verify_key_change(&self, body: &[u8], url: &str) -> Result<KeyChange, Problem> {
        let (outer, signer) = self.verified(body, url, KeyRule::Kid).await?;
        let Signer::Account { account, key } = signer else {
            unreachable!("KeyRule::Kid yields an account")
        };
        let change = outer.key_change(&key, self.provider).map_err(refused)?;
        if change.account != self.account_url(account.id) {
            return Err(malformed("the key change names another account"));
        }
        Ok(KeyChange {
            account,
            new_key: change.new_key,
        })
    }

    async fn verified(
        &self,
        body: &[u8],
        url: &str,
        rule: KeyRule,
    ) -> Result<(FlattenedJws, Signer), Problem> {
        let jws = FlattenedJws::parse(body).map_err(refused)?;
        let header = jws.header();
        if header.url != url {
            return Err(Problem::new(
                ProblemType::Unauthorized,
                format!("the JWS is for {:?}, not {url:?}", header.url),
            ));
        }
        let nonce = header
            .nonce
            .as_deref()
            .ok_or_else(|| Problem::new(ProblemType::BadNonce, "the JWS has no nonce"))?;
        let signer = match (&header.key, rule) {
            (KeyRef::Jwk(jwk), KeyRule::Jwk | KeyRule::Either) => Signer::Key(jwk.clone()),
            (KeyRef::Kid(kid), KeyRule::Kid | KeyRule::Either) => self.account(kid).await?,
            (KeyRef::Jwk(_), KeyRule::Kid) => {
                return Err(malformed("the JWS must name its account by kid"));
            }
            (KeyRef::Kid(_), KeyRule::Jwk) => {
                return Err(malformed("the JWS must carry its key as jwk"));
            }
        };
        jws.verify(signer.key(), self.provider).map_err(refused)?;
        if !self.nonces.redeem(nonce) {
            return Err(Problem::new(
                ProblemType::BadNonce,
                "the nonce is unknown or used",
            ));
        }
        Ok((jws, signer))
    }

    async fn account(&self, kid: &str) -> Result<Signer, Problem> {
        let unknown = || {
            Problem::new(
                ProblemType::AccountDoesNotExist,
                format!("{kid:?} is no account"),
            )
        };
        let id = kid
            .strip_prefix(self.accounts_url)
            .and_then(|id| id.parse().ok())
            .filter(|&id| self.account_url(id) == kid)
            .ok_or_else(unknown)?;
        let account = self
            .store
            .account(id)
            .await
            .map_err(internal)?
            .ok_or_else(unknown)?;
        if account.status != AccountStatus::Valid {
            return Err(Problem::new(
                ProblemType::Unauthorized,
                format!("the account is {}", account.status.as_str()),
            ));
        }
        let key = Jwk::from_json(&account.jwk).map_err(internal)?;
        Ok(Signer::Account { account, key })
    }
}

fn malformed(detail: impl std::fmt::Display) -> Problem {
    Problem::new(ProblemType::Malformed, detail)
}

fn internal(e: impl std::fmt::Display) -> Problem {
    Problem::new(ProblemType::ServerInternal, e)
}

/// RFC 8555 has no badSignature type; a signature that fails is a malformed request.
fn refused(e: JoseError) -> Problem {
    let kind = match e.kind() {
        ErrorKind::BadSignatureAlgorithm => ProblemType::BadSignatureAlgorithm,
        ErrorKind::BadPublicKey => ProblemType::BadPublicKey,
        ErrorKind::ServerConfiguration => ProblemType::ServerInternal,
        _ => ProblemType::Malformed,
    };
    Problem::new(kind, e)
}

/// Replay nonces (RFC 8555 §6.5): random, each redeemable once, the oldest forgotten past `capacity`.
pub struct Nonces {
    provider: Arc<CryptoProvider>,
    capacity: usize,
    state: Mutex<NonceState>,
}

#[derive(Default)]
struct NonceState {
    live: HashSet<String>,
    issued: VecDeque<String>,
}

impl Nonces {
    pub fn new(provider: Arc<CryptoProvider>, capacity: usize) -> Self {
        Self {
            provider,
            capacity,
            state: Mutex::default(),
        }
    }

    pub fn issue(&self) -> Result<String, wslib_crypto::Error> {
        let nonce = base64url(&wslib_crypto::random::<16>(&self.provider)?);
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while state.issued.len() >= self.capacity {
            let Some(oldest) = state.issued.pop_front() else {
                break;
            };
            state.live.remove(&oldest);
        }
        state.issued.push_back(nonce.clone());
        state.live.insert(nonce.clone());
        Ok(nonce)
    }

    /// Whether `nonce` was issued and not yet redeemed or forgotten; it can't be redeemed again.
    pub fn redeem(&self, nonce: &str) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .live
            .remove(nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonces(capacity: usize) -> Nonces {
        Nonces::new(Arc::new(rustls_openssl::default_provider()), capacity)
    }

    #[test]
    fn a_nonce_redeems_once() {
        let nonces = nonces(8);
        let nonce = nonces.issue().unwrap();
        assert_eq!(nonce.len(), 22);
        assert!(nonces.redeem(&nonce));
        assert!(!nonces.redeem(&nonce));
        assert!(!nonces.redeem("never-issued"));
    }

    #[test]
    fn the_oldest_nonce_is_forgotten_past_capacity() {
        let nonces = nonces(3);
        let issued: Vec<_> = (0..5).map(|_| nonces.issue().unwrap()).collect();
        assert_eq!(issued.iter().collect::<HashSet<_>>().len(), 5);
        assert!(!nonces.redeem(&issued[0]));
        assert!(!nonces.redeem(&issued[1]));
        assert!(issued[2..].iter().all(|nonce| nonces.redeem(nonce)));
    }

    #[test]
    fn redeemed_nonces_leave_room_bounded() {
        let nonces = nonces(2);
        for _ in 0..100 {
            assert!(nonces.redeem(&nonces.issue().unwrap()));
        }
        let state = nonces.state.lock().unwrap();
        assert!(state.issued.len() <= 2 && state.live.is_empty());
    }
}
