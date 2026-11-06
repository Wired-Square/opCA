//! `acme.db`: the accounts, orders, authorisations, challenges and certificates the ACME server keeps.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use opca_acme_api::{Challenge as ChallengeType, IssuedCounts};
use rustls::crypto::CryptoProvider;
use serde::Serialize;
use serde::de::DeserializeOwned;
use wslib_db_sqlite::sqlx::error::BoxDynError;
use wslib_db_sqlite::sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};
use wslib_db_sqlite::sqlx::query::Query;
use wslib_db_sqlite::sqlx::sqlite::{SqliteArguments, SqliteConnectOptions, SqliteRow};
use wslib_db_sqlite::sqlx::{
    self, ConnectOptions, Connection, Row, Sqlite, SqliteConnection, Transaction,
};
use wslib_db_sqlite::{Chain, Database, stamp};

use super::{Named, Problem, base64url};

const MIGRATIONS: [(i64, &str, &str); 2] = [
    (
        1,
        "acme store",
        include_str!("../../migrations/0001_acme_store.sql"),
    ),
    (
        2,
        "issued changes",
        include_str!("../../migrations/0002_issued_changes.sql"),
    ),
];

/// The newest migration, which a capture of `acme.db` records.
pub const SCHEMA: i64 = MIGRATIONS[MIGRATIONS.len() - 1].0;

named! {
    pub enum AccountStatus {
        Valid = "valid",
        Deactivated = "deactivated",
        Revoked = "revoked",
    }
}

named! {
    pub enum OrderStatus {
        Pending = "pending",
        Ready = "ready",
        Processing = "processing",
        Valid = "valid",
        Invalid = "invalid",
    }
}

named! {
    pub enum AuthorisationStatus {
        Pending = "pending",
        Valid = "valid",
        Invalid = "invalid",
        Deactivated = "deactivated",
        Expired = "expired",
        Revoked = "revoked",
    }
}

named! {
    pub enum ChallengeStatus {
        Pending = "pending",
        Processing = "processing",
        Valid = "valid",
        Invalid = "invalid",
    }
}

/// A status kept in its table's `status` column, moving only as RFC 8555 §7.1.6 draws it.
trait Lifecycle: Named {
    const TABLE: &'static str;
    fn may_become(self, next: Self) -> bool;
}

impl Lifecycle for AccountStatus {
    const TABLE: &'static str = "accounts";
    fn may_become(self, next: Self) -> bool {
        self == Self::Valid && next != Self::Valid
    }
}

impl Lifecycle for OrderStatus {
    const TABLE: &'static str = "orders";
    fn may_become(self, next: Self) -> bool {
        use OrderStatus::*;
        matches!(
            (self, next),
            (Pending, Ready | Invalid)
                | (Ready, Processing | Invalid)
                | (Processing, Valid | Invalid)
        )
    }
}

impl Lifecycle for AuthorisationStatus {
    const TABLE: &'static str = "authorisations";
    fn may_become(self, next: Self) -> bool {
        use AuthorisationStatus::*;
        matches!(
            (self, next),
            (Pending, Valid | Invalid | Deactivated | Expired)
                | (Valid, Deactivated | Expired | Revoked)
        )
    }
}

impl Lifecycle for ChallengeStatus {
    const TABLE: &'static str = "challenges";
    fn may_become(self, next: Self) -> bool {
        use ChallengeStatus::*;
        matches!(
            (self, next),
            (Pending, Processing) | (Processing, Pending | Valid | Invalid)
        )
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Db(wslib_db_sqlite::Error),
    Random(wslib_crypto::Error),
    NotFound {
        table: &'static str,
        key: String,
    },
    Transition {
        table: &'static str,
        from: &'static str,
        to: &'static str,
    },
    AlreadyRevoked {
        serial: String,
    },
    KeyInUse {
        account: i64,
    },
    Unrestorable(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Db(e) => e.fmt(f),
            Self::Random(e) => write!(f, "minting a token: {e}"),
            Self::NotFound { table, key } => write!(f, "{table} has no row {key}"),
            Self::Transition { table, from, to } => {
                write!(f, "{table}: {from} cannot become {to}")
            }
            Self::AlreadyRevoked { serial } => write!(f, "certificate {serial} is already revoked"),
            Self::KeyInUse { account } => write!(f, "account {account} holds that key"),
            Self::Unrestorable(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

impl From<wslib_db_sqlite::Error> for Error {
    fn from(e: wslib_db_sqlite::Error) -> Self {
        Self::Db(e)
    }
}

impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        Self::Db(e.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: i64,
    /// The account key's JWK in RFC 7638's canonical form.
    pub jwk: String,
    pub thumbprint: String,
    pub status: AccountStatus,
    pub contacts: Vec<String>,
    pub created: SystemTime,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewOrder {
    pub account: i64,
    /// DNS names, lower-case, a wildcard as `*.` and its base.
    pub identifiers: Vec<String>,
    pub not_before: Option<SystemTime>,
    pub not_after: Option<SystemTime>,
    pub expires: SystemTime,
    pub authorisations: Vec<NewAuthorisation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewAuthorisation {
    /// The name validated: a wildcard's base, without its `*.`.
    pub identifier: String,
    pub wildcard: bool,
    pub expires: SystemTime,
    /// One challenge of each, each with a token of its own.
    pub challenges: Vec<ChallengeType>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub id: i64,
    pub account: i64,
    pub status: OrderStatus,
    pub identifiers: Vec<String>,
    pub not_before: Option<SystemTime>,
    pub not_after: Option<SystemTime>,
    pub expires: SystemTime,
    pub error: Option<Problem>,
    pub certificate: Option<i64>,
    pub authorisations: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorisation {
    pub id: i64,
    pub order: i64,
    pub identifier: String,
    pub wildcard: bool,
    pub status: AuthorisationStatus,
    pub expires: SystemTime,
    pub challenges: Vec<Challenge>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub id: i64,
    pub authorisation: i64,
    pub kind: ChallengeType,
    pub token: String,
    pub status: ChallengeStatus,
    pub validated: Option<SystemTime>,
    pub error: Option<Problem>,
}

/// An issued certificate, as [`Store::record_certificate`] takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCertificate {
    /// Decimal.
    pub serial: String,
    pub common_name: Option<String>,
    pub sans: Vec<String>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    /// The leaf, then the chain up to and excluding the root.
    pub chain_pem: String,
    /// The subordinate's, decimal.
    pub issuer_serial: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub id: i64,
    pub serial: String,
    pub account: i64,
    pub order: i64,
    pub common_name: Option<String>,
    pub sans: Vec<String>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub chain_pem: String,
    pub issuer_serial: String,
    pub revoked_at: Option<SystemTime>,
    /// An RFC 5280 CRLReason code; `None` is unspecified.
    pub revocation_reason: Option<u8>,
    pub created: SystemTime,
    /// Taken afresh, above every other, on insert and on revoke: the cursor of [`Store::changed_after`].
    pub changed: i64,
}

/// What [`Store::changed_after`] or [`Store::newest`] found: the certificates, and whether more wait past them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changes {
    pub certificates: Vec<Certificate>,
    pub more: bool,
}

/// A challenge to validate, with what its validation needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validation {
    pub challenge: i64,
    pub kind: ChallengeType,
    /// The name validated: a wildcard's base.
    pub identifier: String,
    pub key_authorisation: String,
}

/// What [`Store::expire_stale`] moved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Expired {
    pub orders: u64,
    pub authorisations: u64,
}

const ACCOUNT: &str = "SELECT id, jwk, thumbprint, status, contacts, created FROM accounts";
const ORDER: &str = "SELECT id, account, status, identifiers, not_before, not_after, expires, \
                     error, certificate FROM orders";
const AUTHORISATION: &str =
    "SELECT id, order_id, identifier, wildcard, status, expires FROM authorisations";
const CHALLENGE: &str =
    "SELECT id, authorisation, type, token, status, validated, error FROM challenges";
const CERTIFICATE: &str = "SELECT id, serial, account, order_id, common_name, sans, not_before, \
                           not_after, chain_pem, issuer_serial, revoked_at, revocation_reason, \
                           created, changed FROM certificates";

/// Bound twice to a JSON array of issuer serials, or to NULL for every issuer.
const ISSUED_BY: &str = "(? IS NULL OR issuer_serial IN (SELECT value FROM json_each(?)))";

const DANGLING: &str = "a row in it refers to one that is not there";

const NEXT_CHANGE: &str = "(SELECT COALESCE(MAX(changed), 0) + 1 FROM certificates)";

/// An order cannot be ready once any of its authorisations has failed or gone.
const FAIL_ORDERS: &str = "UPDATE orders SET status = 'invalid' \
                           WHERE status IN ('pending', 'ready') AND EXISTS (\
                           SELECT 1 FROM authorisations a WHERE a.order_id = orders.id \
                           AND a.status NOT IN ('pending', 'valid'))";

/// The ACME server's database, opened from `Broker::start`.
#[derive(Clone, Debug)]
pub struct Store {
    db: Database,
    provider: Arc<CryptoProvider>,
}

#[derive(Debug)]
struct Migrations;

impl MigrationSource<'static> for Migrations {
    fn resolve(
        self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<Migration>, BoxDynError>> + Send + 'static>>
    {
        Box::pin(async {
            Ok(MIGRATIONS
                .iter()
                .map(|&(version, description, sql)| {
                    Migration::new(
                        version,
                        description.into(),
                        MigrationType::Simple,
                        sql.into(),
                        false,
                    )
                })
                .collect())
        })
    }
}

impl Store {
    /// Opens `path`, creating it and applying every pending migration; tokens come from `provider`.
    pub async fn open(path: &Path, provider: Arc<CryptoProvider>) -> Result<Self, Error> {
        let migrator =
            Migrator::new(Migrations)
                .await
                .map_err(|source| wslib_db_sqlite::Error::Migrate {
                    chain: "acme".into(),
                    source,
                })?;
        let db = Database::open(path, &[Chain::new("acme", &migrator)]).await?;
        Ok(Self { db, provider })
    }

    /// The account for `thumbprint`, made with `jwk` and `contacts` when there is none; and whether this call made it.
    pub async fn create_account(
        &self,
        jwk: &str,
        thumbprint: &str,
        contacts: &[String],
    ) -> Result<(Account, bool), Error> {
        let mut tx = self.db.begin().await?;
        let made = sqlx::query(
            "INSERT INTO accounts (jwk, thumbprint, status, contacts, created) \
             VALUES (?, ?, 'valid', ?, ?) ON CONFLICT (thumbprint) DO NOTHING",
        )
        .bind(jwk)
        .bind(thumbprint)
        .bind(json(contacts))
        .bind(now())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let account = one(
            &mut tx,
            ACCOUNT,
            "thumbprint = ?",
            thumbprint.to_owned(),
            account,
        )
        .await?
        .expect("the account is there, made or found");
        tx.commit().await?;
        Ok((account, made))
    }

    pub async fn account(&self, id: i64) -> Result<Option<Account>, Error> {
        one(
            &mut *self.db.pool().acquire().await?,
            ACCOUNT,
            "id = ?",
            id,
            account,
        )
        .await
    }

    pub async fn account_by_thumbprint(&self, thumbprint: &str) -> Result<Option<Account>, Error> {
        let conn = &mut *self.db.pool().acquire().await?;
        one(
            conn,
            ACCOUNT,
            "thumbprint = ?",
            thumbprint.to_owned(),
            account,
        )
        .await
    }

    pub async fn set_contacts(&self, id: i64, contacts: &[String]) -> Result<(), Error> {
        sqlx::query("UPDATE accounts SET contacts = ? WHERE id = ?")
            .bind(json(contacts))
            .bind(id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// Gives account `id` the key `jwk`, unless another account holds it.
    pub async fn change_key(&self, id: i64, jwk: &str, thumbprint: &str) -> Result<(), Error> {
        let mut tx = self.db.begin().await?;
        let holder: Option<i64> =
            sqlx::query_scalar("SELECT id FROM accounts WHERE thumbprint = ?")
                .bind(thumbprint)
                .fetch_optional(&mut *tx)
                .await?;
        if let Some(account) = holder.filter(|&holder| holder != id) {
            return Err(Error::KeyInUse { account });
        }
        sqlx::query("UPDATE accounts SET jwk = ?, thumbprint = ? WHERE id = ?")
            .bind(jwk)
            .bind(thumbprint)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn orders_of(&self, account: i64) -> Result<Vec<i64>, Error> {
        Ok(
            sqlx::query_scalar("SELECT id FROM orders WHERE account = ? ORDER BY id")
                .bind(account)
                .fetch_all(self.db.pool())
                .await?,
        )
    }

    pub async fn set_account_status(&self, id: i64, to: AccountStatus) -> Result<(), Error> {
        let mut tx = self.db.begin().await?;
        transition(&mut tx, id, to).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A pending order, with its authorisations and their challenges, all pending.
    pub async fn create_order(&self, new: &NewOrder) -> Result<Order, Error> {
        let mut tx = self.db.begin().await?;
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO orders (account, status, identifiers, not_before, not_after, expires, \
             created) VALUES (?, 'pending', ?, ?, ?, ?, ?) RETURNING id",
        )
        .bind(new.account)
        .bind(json(&new.identifiers))
        .bind(new.not_before.map(format))
        .bind(new.not_after.map(format))
        .bind(format(new.expires))
        .bind(now())
        .fetch_one(&mut *tx)
        .await?;
        for authorisation in &new.authorisations {
            let authorisation_id: i64 = sqlx::query_scalar(
                "INSERT INTO authorisations (order_id, identifier, wildcard, status, expires) \
                 VALUES (?, ?, ?, 'pending', ?) RETURNING id",
            )
            .bind(id)
            .bind(&authorisation.identifier)
            .bind(authorisation.wildcard)
            .bind(format(authorisation.expires))
            .fetch_one(&mut *tx)
            .await?;
            for kind in &authorisation.challenges {
                let token =
                    base64url(&wslib_crypto::random::<32>(&self.provider).map_err(Error::Random)?);
                sqlx::query(
                    "INSERT INTO challenges (authorisation, type, token, status) \
                     VALUES (?, ?, ?, 'pending')",
                )
                .bind(authorisation_id)
                .bind(challenge_name(*kind))
                .bind(token)
                .execute(&mut *tx)
                .await?;
            }
        }
        let order = order(&mut tx, id).await?.expect("the order was just made");
        tx.commit().await?;
        Ok(order)
    }

    pub async fn order(&self, id: i64) -> Result<Option<Order>, Error> {
        order(&mut *self.db.pool().acquire().await?, id).await
    }

    pub async fn authorisation(&self, id: i64) -> Result<Option<Authorisation>, Error> {
        let mut conn = self.db.pool().acquire().await?;
        let Some(row) = sqlx::query(&format!("{AUTHORISATION} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?
        else {
            return Ok(None);
        };
        let challenges = sqlx::query(&format!("{CHALLENGE} WHERE authorisation = ? ORDER BY id"))
            .bind(id)
            .fetch_all(&mut *conn)
            .await?
            .iter()
            .map(challenge)
            .collect::<Result<_, _>>()?;
        Ok(Some(Authorisation {
            id,
            order: row.try_get("order_id")?,
            identifier: row.try_get("identifier")?,
            wildcard: row.try_get("wildcard")?,
            status: status(&row, "authorisations")?,
            expires: time(&row, "authorisations", "expires")?,
            challenges,
        }))
    }

    pub async fn challenge(&self, id: i64) -> Result<Option<Challenge>, Error> {
        one(
            &mut *self.db.pool().acquire().await?,
            CHALLENGE,
            "id = ?",
            id,
            challenge,
        )
        .await
    }

    pub async fn set_order_status(
        &self,
        id: i64,
        to: OrderStatus,
        error: Option<&Problem>,
    ) -> Result<(), Error> {
        let mut tx = self.db.begin().await?;
        transition(&mut tx, id, to).await?;
        set_error("orders", &mut tx, id, error).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Also settles the order: invalid once this fails, ready once every authorisation is valid.
    pub async fn set_authorisation_status(
        &self,
        id: i64,
        to: AuthorisationStatus,
    ) -> Result<(), Error> {
        let mut tx = self.db.begin().await?;
        transition(&mut tx, id, to).await?;
        settle_order_of(&mut tx, id).await?;
        tx.commit().await?;
        Ok(())
    }

    /// A valid or invalid challenge decides its pending authorisation, and so perhaps the order.
    pub async fn set_challenge_status(
        &self,
        id: i64,
        to: ChallengeStatus,
        error: Option<&Problem>,
    ) -> Result<(), Error> {
        let mut tx = self.db.begin().await?;
        transition(&mut tx, id, to).await?;
        set_error("challenges", &mut tx, id, error).await?;
        let decided = match to {
            ChallengeStatus::Valid => AuthorisationStatus::Valid,
            ChallengeStatus::Invalid => AuthorisationStatus::Invalid,
            ChallengeStatus::Pending | ChallengeStatus::Processing => {
                return Ok(tx.commit().await?);
            }
        };
        let authorisation: i64 = sqlx::query_scalar(
            "UPDATE challenges SET validated = CASE WHEN status = 'valid' THEN ? END \
             WHERE id = ? RETURNING authorisation",
        )
        .bind(now())
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE authorisations SET status = ? WHERE id = ? AND status = 'pending'")
            .bind(decided.as_str())
            .bind(authorisation)
            .execute(&mut *tx)
            .await?;
        settle_order_of(&mut tx, authorisation).await?;
        Ok(tx.commit().await?)
    }

    /// Records `issued` for a ready or processing order, which becomes valid and names it.
    pub async fn record_certificate(
        &self,
        order_id: i64,
        issued: &NewCertificate,
    ) -> Result<Certificate, Error> {
        let mut tx = self.db.begin().await?;
        if read_status::<OrderStatus>(&mut tx, order_id).await? == OrderStatus::Ready {
            transition(&mut tx, order_id, OrderStatus::Processing).await?;
        }
        transition(&mut tx, order_id, OrderStatus::Valid).await?;
        let id: i64 = sqlx::query_scalar(&format!(
            "INSERT INTO certificates (serial, account, order_id, common_name, sans, not_before, \
             not_after, chain_pem, issuer_serial, created, changed) \
             SELECT ?, account, id, ?, ?, ?, ?, ?, ?, ?, {NEXT_CHANGE} FROM orders WHERE id = ? \
             RETURNING id"
        ))
        .bind(&issued.serial)
        .bind(&issued.common_name)
        .bind(json(&issued.sans))
        .bind(format(issued.not_before))
        .bind(format(issued.not_after))
        .bind(&issued.chain_pem)
        .bind(&issued.issuer_serial)
        .bind(now())
        .bind(order_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE orders SET certificate = ? WHERE id = ?")
            .bind(id)
            .bind(order_id)
            .execute(&mut *tx)
            .await?;
        let recorded = one(&mut tx, CERTIFICATE, "id = ?", id, certificate).await?;
        tx.commit().await?;
        Ok(recorded.expect("the certificate was just recorded"))
    }

    pub async fn certificate(&self, id: i64) -> Result<Option<Certificate>, Error> {
        one(
            &mut *self.db.pool().acquire().await?,
            CERTIFICATE,
            "id = ?",
            id,
            certificate,
        )
        .await
    }

    pub async fn certificate_by_serial(&self, serial: &str) -> Result<Option<Certificate>, Error> {
        one(
            &mut *self.db.pool().acquire().await?,
            CERTIFICATE,
            "serial = ?",
            serial.to_owned(),
            certificate,
        )
        .await
    }

    /// Marks the certificate with `serial` revoked now, for `reason`.
    pub async fn revoke(&self, serial: &str, reason: Option<u8>) -> Result<Certificate, Error> {
        let mut tx = self.db.begin().await?;
        let revoked = sqlx::query(&format!(
            "UPDATE certificates SET revoked_at = ?, revocation_reason = ?, changed = {NEXT_CHANGE} \
             WHERE serial = ? AND revoked_at IS NULL"
        ))
        .bind(now())
        .bind(reason)
        .bind(serial)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let Some(certificate) = one(
            &mut tx,
            CERTIFICATE,
            "serial = ?",
            serial.to_owned(),
            certificate,
        )
        .await?
        else {
            return Err(Error::NotFound {
                table: "certificates",
                key: serial.into(),
            });
        };
        if !revoked {
            return Err(Error::AlreadyRevoked {
                serial: serial.into(),
            });
        }
        tx.commit().await?;
        Ok(certificate)
    }

    /// Up to `limit` certificates issued or revoked after change `cursor`, oldest change first; 0 starts at the beginning.
    /// Only those the subordinates with serials `issuers` issued, when given.
    pub async fn changed_after(
        &self,
        cursor: i64,
        issuers: Option<&[String]>,
        limit: u32,
    ) -> Result<Changes, Error> {
        let issuers = issuers.map(json);
        let sql =
            format!("{CERTIFICATE} WHERE changed > ? AND {ISSUED_BY} ORDER BY changed LIMIT ?");
        let query = sqlx::query(&sql).bind(cursor).bind(&issuers).bind(&issuers);
        self.page(query, limit).await
    }

    /// Up to `limit` certificates issued before the one with id `before`,
    /// newest first, and only the revoked or the unrevoked when `revoked` says
    /// which; `None` starts at the newest.
    pub async fn newest(
        &self,
        before: Option<i64>,
        revoked: Option<bool>,
        limit: u32,
    ) -> Result<Changes, Error> {
        let only = match revoked {
            None => "",
            Some(true) => "AND revoked_at IS NOT NULL",
            Some(false) => "AND revoked_at IS NULL",
        };
        let sql = format!("{CERTIFICATE} WHERE id < ? {only} ORDER BY id DESC LIMIT ?");
        let query = sqlx::query(&sql).bind(before.unwrap_or(i64::MAX));
        self.page(query, limit).await
    }

    /// `query` with its `LIMIT ?` left to bind.
    async fn page<'q>(
        &self,
        query: Query<'q, Sqlite, SqliteArguments<'q>>,
        limit: u32,
    ) -> Result<Changes, Error> {
        let mut certificates = query
            .bind(i64::from(limit) + 1)
            .fetch_all(self.db.pool())
            .await?
            .iter()
            .map(certificate)
            .collect::<Result<Vec<_>, _>>()?;
        let more = certificates.len() > limit as usize;
        certificates.truncate(limit as usize);
        Ok(Changes { certificates, more })
    }

    /// Of only the certificates the subordinates with serials `issuers` issued, when given.
    pub async fn counts(&self, issuers: Option<&[String]>) -> Result<IssuedCounts, Error> {
        let issuers = issuers.map(json);
        let sql = format!("SELECT COUNT(*), COUNT(revoked_at) FROM certificates WHERE {ISSUED_BY}");
        let (total, revoked): (i64, i64) = sqlx::query_as(&sql)
            .bind(&issuers)
            .bind(&issuers)
            .fetch_one(self.db.pool())
            .await?;
        Ok(IssuedCounts {
            total: total as u64,
            revoked: revoked as u64,
        })
    }

    /// The challenges being validated, as a restart left them.
    pub async fn processing(&self) -> Result<Vec<Validation>, Error> {
        sqlx::query(
            "SELECT c.id, c.type, c.token, a.identifier, k.thumbprint FROM challenges c \
             JOIN authorisations a ON a.id = c.authorisation \
             JOIN orders o ON o.id = a.order_id JOIN accounts k ON k.id = o.account \
             WHERE c.status = 'processing'",
        )
        .fetch_all(self.db.pool())
        .await?
        .iter()
        .map(|row| {
            let token: &str = row.try_get("token")?;
            let thumbprint: &str = row.try_get("thumbprint")?;
            Ok(Validation {
                challenge: row.try_get("id")?,
                kind: challenge_type(row)?,
                identifier: row.try_get("identifier")?,
                key_authorisation: format!("{token}.{thumbprint}"),
            })
        })
        .collect()
    }

    /// Pending or ready orders and pending or valid authorisations whose time is up at `now`.
    pub async fn expire_stale(&self, now: SystemTime) -> Result<Expired, Error> {
        let now = format(now);
        let mut tx = self.db.begin().await?;
        let authorisations = sqlx::query(
            "UPDATE authorisations SET status = 'expired' \
             WHERE status IN ('pending', 'valid') AND expires <= ?",
        )
        .bind(&now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let expired = sqlx::query(
            "UPDATE orders SET status = 'invalid' \
             WHERE status IN ('pending', 'ready') AND expires <= ?",
        )
        .bind(&now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        let failed = sqlx::query(FAIL_ORDERS)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(Expired {
            orders: expired + failed,
            authorisations,
        })
    }

    /// A consistent copy at `path`, taken live, keeping no chain of a certificate expired at `now`.
    pub async fn snapshot(&self, path: &Path, now: SystemTime) -> Result<(), Error> {
        sqlx::query("VACUUM INTO ?")
            .bind(path.to_string_lossy().into_owned())
            .execute(self.db.pool())
            .await?;
        let mut copy = SqliteConnectOptions::new().filename(path).connect().await?;
        sqlx::query("UPDATE certificates SET chain_pem = '' WHERE not_after <= ?")
            .bind(format(now))
            .execute(&mut copy)
            .await?;
        sqlx::query("PRAGMA journal_mode = DELETE")
            .execute(&mut copy)
            .await?;
        sqlx::query("VACUUM").execute(&mut copy).await?;
        copy.close().await?;
        Ok(())
    }

    /// Opens the copy at `path`, migrated forward, and counts its certificates;
    /// refused unless it is whole and has this database's tables.
    pub async fn open_restorable(&self, path: &Path) -> Result<u64, Error> {
        let copy = Self::open(path, self.provider.clone()).await?;
        let checked = copy.restorable_beside(self).await;
        copy.db.close().await;
        checked
    }

    async fn restorable_beside(&self, live: &Self) -> Result<u64, Error> {
        let pool = self.db.pool();
        let integrity: String = sqlx::query_scalar("PRAGMA integrity_check")
            .fetch_one(pool)
            .await?;
        if integrity != "ok" {
            return Err(Error::Unrestorable("it is damaged"));
        }
        if sqlx::query("PRAGMA foreign_key_check")
            .fetch_optional(pool)
            .await?
            .is_some()
        {
            return Err(Error::Unrestorable(DANGLING));
        }
        if schema(self).await? != schema(live).await? {
            return Err(Error::Unrestorable("its tables are not this broker's"));
        }
        Ok(self.counts(None).await?.total)
    }

    /// Every row replaced by those of the copy at `path`, which [`Store::open_restorable`]
    /// passed, in one transaction that `before_commit` may still refuse. Each
    /// certificate's change moves past every change either database made, so a
    /// sync cursor from before the restore misses nothing after it.
    pub async fn replace_from<E: From<Error>>(
        &self,
        path: &Path,
        before_commit: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), E> {
        // Out of the pool, so the attachment never reaches another query.
        let mut conn = self
            .db
            .writer()
            .acquire()
            .await
            .map_err(Error::from)?
            .detach();
        let tx = replaced(&mut conn, path).await?;
        before_commit()?;
        tx.commit().await.map_err(Error::from)?;
        Ok(())
    }
}

async fn schema(store: &Store) -> Result<Vec<(String, String, String)>, Error> {
    Ok(sqlx::query_as(
        "SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name",
    )
    .fetch_all(store.db.pool())
    .await?)
}

async fn replaced<'c>(
    conn: &'c mut SqliteConnection,
    path: &Path,
) -> Result<Transaction<'c, Sqlite>, Error> {
    sqlx::query("ATTACH DATABASE ? AS restored")
        .bind(path.to_string_lossy().into_owned())
        .execute(&mut *conn)
        .await?;
    // Off, and checked whole before the commit: deferred, a whole-table replace
    // failed its commit with no violation left.
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;
    let mut tx = conn.begin_with("BEGIN IMMEDIATE").await?;
    let past: i64 = sqlx::query_scalar(
        "SELECT MAX((SELECT COALESCE(MAX(changed), 0) FROM main.certificates), \
         (SELECT COALESCE(MAX(changed), 0) FROM restored.certificates))",
    )
    .fetch_one(&mut *tx)
    .await?;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM main.sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_%' ESCAPE '\\'",
    )
    .fetch_all(&mut *tx)
    .await?;
    for table in tables {
        sqlx::query(&format!("DELETE FROM main.\"{table}\""))
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!(
            "INSERT INTO main.\"{table}\" SELECT * FROM restored.\"{table}\""
        ))
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE main.certificates SET changed = changed + ?")
        .bind(past)
        .execute(&mut *tx)
        .await?;
    if sqlx::query("PRAGMA main.foreign_key_check")
        .fetch_optional(&mut *tx)
        .await?
        .is_some()
    {
        return Err(Error::Unrestorable(
            "a row in it refers to one that is not there",
        ));
    }
    Ok(tx)
}

async fn read_status<S: Lifecycle>(conn: &mut SqliteConnection, id: i64) -> Result<S, Error> {
    let select = format!("SELECT status FROM {}", S::TABLE);
    one(conn, &select, "id = ?", id, |row| status(row, S::TABLE))
        .await?
        .ok_or_else(|| Error::NotFound {
            table: S::TABLE,
            key: id.to_string(),
        })
}

async fn transition<S: Lifecycle>(
    conn: &mut SqliteConnection,
    id: i64,
    to: S,
) -> Result<(), Error> {
    let from = read_status::<S>(conn, id).await?;
    if !from.may_become(to) {
        return Err(Error::Transition {
            table: S::TABLE,
            from: from.as_str(),
            to: to.as_str(),
        });
    }
    sqlx::query(&format!("UPDATE {} SET status = ? WHERE id = ?", S::TABLE))
        .bind(to.as_str())
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn set_error(
    table: &str,
    conn: &mut SqliteConnection,
    id: i64,
    error: Option<&Problem>,
) -> Result<(), Error> {
    sqlx::query(&format!("UPDATE {table} SET error = ? WHERE id = ?"))
        .bind(error.map(json))
        .bind(id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn settle_order_of(conn: &mut SqliteConnection, authorisation: i64) -> Result<(), Error> {
    let order: i64 = sqlx::query_scalar("SELECT order_id FROM authorisations WHERE id = ?")
        .bind(authorisation)
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query(&format!("{FAIL_ORDERS} AND id = ?"))
        .bind(order)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "UPDATE orders SET status = 'ready' WHERE id = ? AND status = 'pending' AND NOT EXISTS (\
         SELECT 1 FROM authorisations a WHERE a.order_id = orders.id AND a.status <> 'valid')",
    )
    .bind(order)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn order(conn: &mut SqliteConnection, id: i64) -> Result<Option<Order>, Error> {
    let Some(row) = sqlx::query(&format!("{ORDER} WHERE id = ?"))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
    else {
        return Ok(None);
    };
    let authorisations =
        sqlx::query_scalar("SELECT id FROM authorisations WHERE order_id = ? ORDER BY id")
            .bind(id)
            .fetch_all(&mut *conn)
            .await?;
    Ok(Some(Order {
        id,
        account: row.try_get("account")?,
        status: status(&row, "orders")?,
        identifiers: from_json(&row, "orders", "identifiers")?,
        not_before: optional_time(&row, "orders", "not_before")?,
        not_after: optional_time(&row, "orders", "not_after")?,
        expires: time(&row, "orders", "expires")?,
        error: from_json(&row, "orders", "error")?,
        certificate: row.try_get("certificate")?,
        authorisations,
    }))
}

/// The row `select … WHERE filter` finds for `key`, read by `read`.
async fn one<T>(
    conn: &mut SqliteConnection,
    select: &str,
    filter: &str,
    key: impl for<'q> sqlx::Encode<'q, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite> + Send,
    read: impl Fn(&SqliteRow) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    sqlx::query(&format!("{select} WHERE {filter}"))
        .bind(key)
        .fetch_optional(&mut *conn)
        .await?
        .as_ref()
        .map(read)
        .transpose()
}

fn account(row: &SqliteRow) -> Result<Account, Error> {
    Ok(Account {
        id: row.try_get("id")?,
        jwk: row.try_get("jwk")?,
        thumbprint: row.try_get("thumbprint")?,
        status: status(row, "accounts")?,
        contacts: from_json(row, "accounts", "contacts")?,
        created: time(row, "accounts", "created")?,
    })
}

fn challenge_type(row: &SqliteRow) -> Result<ChallengeType, Error> {
    let kind: &str = row.try_get("type")?;
    parse_challenge(kind).ok_or_else(|| {
        wslib_db_sqlite::Error::unreadable("challenges", "type", format!("{kind:?}")).into()
    })
}

fn challenge(row: &SqliteRow) -> Result<Challenge, Error> {
    Ok(Challenge {
        id: row.try_get("id")?,
        authorisation: row.try_get("authorisation")?,
        kind: challenge_type(row)?,
        token: row.try_get("token")?,
        status: status(row, "challenges")?,
        validated: optional_time(row, "challenges", "validated")?,
        error: from_json(row, "challenges", "error")?,
    })
}

fn certificate(row: &SqliteRow) -> Result<Certificate, Error> {
    Ok(Certificate {
        id: row.try_get("id")?,
        serial: row.try_get("serial")?,
        account: row.try_get("account")?,
        order: row.try_get("order_id")?,
        common_name: row.try_get("common_name")?,
        sans: from_json(row, "certificates", "sans")?,
        not_before: time(row, "certificates", "not_before")?,
        not_after: time(row, "certificates", "not_after")?,
        chain_pem: row.try_get("chain_pem")?,
        issuer_serial: row.try_get("issuer_serial")?,
        revoked_at: optional_time(row, "certificates", "revoked_at")?,
        revocation_reason: row.try_get("revocation_reason")?,
        created: time(row, "certificates", "created")?,
        changed: row.try_get("changed")?,
    })
}

fn challenge_name(kind: ChallengeType) -> &'static str {
    match kind {
        ChallengeType::Http01 => "http-01",
        ChallengeType::Dns01 => "dns-01",
        ChallengeType::TlsAlpn01 => "tls-alpn-01",
    }
}

fn parse_challenge(name: &str) -> Option<ChallengeType> {
    [
        ChallengeType::Http01,
        ChallengeType::Dns01,
        ChallengeType::TlsAlpn01,
    ]
    .into_iter()
    .find(|kind| challenge_name(*kind) == name)
}

fn status<S: Named>(row: &SqliteRow, table: &'static str) -> Result<S, Error> {
    let text: &str = row.try_get("status")?;
    S::parse(text).ok_or_else(|| {
        wslib_db_sqlite::Error::unreadable(table, "status", format!("{text:?}")).into()
    })
}

fn now() -> String {
    stamp::format(stamp::now())
}

pub(crate) fn format(at: SystemTime) -> String {
    stamp::format(at.into())
}

fn time(row: &SqliteRow, table: &'static str, column: &'static str) -> Result<SystemTime, Error> {
    Ok(stamp::from_row(row, table, column)?.into())
}

fn optional_time(
    row: &SqliteRow,
    table: &'static str,
    column: &'static str,
) -> Result<Option<SystemTime>, Error> {
    let text: Option<&str> = row.try_get(column)?;
    Ok(text
        .map(|text| stamp::parse(table, column, text))
        .transpose()?
        .map(Into::into))
}

fn json(value: &(impl Serialize + ?Sized)) -> String {
    serde_json::to_string(value).expect("strings and problems serialise")
}

/// A NULL reads as JSON `null`, so an `Option` column reads as `None`.
fn from_json<T: DeserializeOwned>(
    row: &SqliteRow,
    table: &'static str,
    column: &'static str,
) -> Result<T, Error> {
    let text: Option<&str> = row.try_get(column)?;
    serde_json::from_str(text.unwrap_or("null"))
        .map_err(|e| wslib_db_sqlite::Error::unreadable(table, column, e).into())
}
