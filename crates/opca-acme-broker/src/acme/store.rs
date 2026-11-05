//! `acme.db`: the accounts, orders, authorisations, challenges and certificates the ACME server keeps.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use opca_acme_api::Challenge as ChallengeType;
use rustls::crypto::CryptoProvider;
use serde::Serialize;
use serde::de::DeserializeOwned;
use wslib_db_sqlite::sqlx::error::BoxDynError;
use wslib_db_sqlite::sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};
use wslib_db_sqlite::sqlx::sqlite::SqliteRow;
use wslib_db_sqlite::sqlx::{self, Row, SqliteConnection};
use wslib_db_sqlite::{Chain, Database, stamp};

use super::{Named, Problem, base64url};

const MIGRATIONS: [(i64, &str, &str); 1] = [(
    1,
    "acme store",
    include_str!("../../migrations/0001_acme_store.sql"),
)];

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Only grows, and is never reused: the cursor of [`Store::issued_after`].
    pub id: i64,
    pub serial: String,
    pub account: i64,
    pub order: i64,
    pub common_name: Option<String>,
    pub sans: Vec<String>,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub chain_pem: String,
    pub revoked_at: Option<SystemTime>,
    /// An RFC 5280 CRLReason code; `None` is unspecified.
    pub revocation_reason: Option<u8>,
    pub created: SystemTime,
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
                           not_after, chain_pem, revoked_at, revocation_reason, created \
                           FROM certificates";

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
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO certificates (serial, account, order_id, common_name, sans, not_before, \
             not_after, chain_pem, created) \
             SELECT ?, account, id, ?, ?, ?, ?, ?, ? FROM orders WHERE id = ? RETURNING id",
        )
        .bind(&issued.serial)
        .bind(&issued.common_name)
        .bind(json(&issued.sans))
        .bind(format(issued.not_before))
        .bind(format(issued.not_after))
        .bind(&issued.chain_pem)
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

    /// Marks the certificate with `serial` revoked now, for `reason`.
    pub async fn revoke(&self, serial: &str, reason: Option<u8>) -> Result<Certificate, Error> {
        let mut tx = self.db.begin().await?;
        let revoked = sqlx::query(
            "UPDATE certificates SET revoked_at = ?, revocation_reason = ? \
             WHERE serial = ? AND revoked_at IS NULL",
        )
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

    /// Up to `limit` certificates recorded after the one with id `cursor`, oldest first; 0 starts at the beginning.
    pub async fn issued_after(&self, cursor: i64, limit: u32) -> Result<Vec<Certificate>, Error> {
        sqlx::query(&format!("{CERTIFICATE} WHERE id > ? ORDER BY id LIMIT ?"))
            .bind(cursor)
            .bind(limit)
            .fetch_all(self.db.pool())
            .await?
            .iter()
            .map(certificate)
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

fn challenge(row: &SqliteRow) -> Result<Challenge, Error> {
    let kind: &str = row.try_get("type")?;
    Ok(Challenge {
        id: row.try_get("id")?,
        authorisation: row.try_get("authorisation")?,
        kind: parse_challenge(kind).ok_or_else(|| {
            wslib_db_sqlite::Error::unreadable("challenges", "type", format!("{kind:?}"))
        })?,
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
        revoked_at: optional_time(row, "certificates", "revoked_at")?,
        revocation_reason: row.try_get("revocation_reason")?,
        created: time(row, "certificates", "created")?,
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

fn format(at: SystemTime) -> String {
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
