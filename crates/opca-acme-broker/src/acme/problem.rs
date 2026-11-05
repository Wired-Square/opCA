use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const PREFIX: &str = "urn:ietf:params:acme:error:";

named! {
    /// RFC 8555 §6.7's error types.
    pub enum ProblemType {
        AccountDoesNotExist = "accountDoesNotExist",
        AlreadyRevoked = "alreadyRevoked",
        BadCsr = "badCSR",
        BadNonce = "badNonce",
        BadPublicKey = "badPublicKey",
        BadRevocationReason = "badRevocationReason",
        BadSignatureAlgorithm = "badSignatureAlgorithm",
        Caa = "caa",
        Compound = "compound",
        Connection = "connection",
        Dns = "dns",
        ExternalAccountRequired = "externalAccountRequired",
        IncorrectResponse = "incorrectResponse",
        InvalidContact = "invalidContact",
        Malformed = "malformed",
        OrderNotReady = "orderNotReady",
        RateLimited = "rateLimited",
        RejectedIdentifier = "rejectedIdentifier",
        ServerInternal = "serverInternal",
        Tls = "tls",
        Unauthorized = "unauthorized",
        UnsupportedContact = "unsupportedContact",
        UnsupportedIdentifier = "unsupportedIdentifier",
        UserActionRequired = "userActionRequired",
    }
}

impl ProblemType {
    pub fn urn(self) -> String {
        format!("{PREFIX}{}", self.as_str())
    }
}

impl Serialize for ProblemType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.urn())
    }
}

impl<'de> Deserialize<'de> for ProblemType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let urn = String::deserialize(deserializer)?;
        urn.strip_prefix(PREFIX)
            .and_then(Self::parse)
            .ok_or_else(|| D::Error::custom(format!("{urn:?} is not an ACME error type")))
    }
}

/// An ACME problem document (RFC 7807), as an order or challenge records it and the API serves it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: ProblemType,
    pub detail: String,
}

impl Problem {
    pub fn new(kind: ProblemType, detail: impl fmt::Display) -> Self {
        Self {
            kind,
            detail: detail.to_string(),
        }
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind.as_str(), self.detail)
    }
}

impl std::error::Error for Problem {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_problem_names_its_type_by_urn() {
        let problem = Problem::new(ProblemType::BadCsr, "no names");
        let json = serde_json::to_string(&problem).unwrap();
        assert_eq!(
            json,
            r#"{"type":"urn:ietf:params:acme:error:badCSR","detail":"no names"}"#
        );
        assert_eq!(serde_json::from_str::<Problem>(&json).unwrap(), problem);
        assert!(serde_json::from_str::<Problem>(r#"{"type":"badCSR","detail":""}"#).is_err());
    }
}
