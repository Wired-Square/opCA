//! The app's hot backup (decision 25-20): `acme.db` and the enrolment, never the subordinate key.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use opca_acme_api::ErrorBody;
use rustls_openssl::default_provider;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use wslib_appliance_types::backup::{Chosen, RestoreReport};
use wslib_appliance_types::hooks::{AppInspection, AppRestore};
use wslib_crypto_x509::{inspect, pem};

use crate::acme::store::{SCHEMA, Store};
use crate::acme::{base64url, from_base64url};
use crate::broker::lock_state;
use crate::enrolment::{self, Enrolled, Mode, bad_request, decimal, rfc_3339};
use crate::{Broker, Error};

pub const FORMAT: &str = "opca-acme-broker";
pub const VERSION: u32 = 1;
pub const ACME: &str = "acme";
pub const ENROLMENT: &str = "enrolment";

/// Well past any `acme.db` whose capture fits the console's 7 MiB.
const LARGEST_DB: u64 = 128 << 20;

/// What a capture answers and a restore takes back, the sections at the top.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub format: String,
    pub version: u32,
    pub app_version: String,
    pub taken_at: String,
    pub acme: Option<Value>,
    pub enrolment: Option<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcmeSection {
    schema: i64,
    /// `acme.db`, deflated, in base64url.
    db: String,
}

impl Capture {
    pub fn new(acme: Option<Value>, enrolment: Option<Value>) -> Self {
        Self {
            format: FORMAT.into(),
            version: VERSION,
            app_version: env!("CARGO_PKG_VERSION").into(),
            taken_at: rfc_3339(SystemTime::now()),
            acme,
            enrolment,
        }
    }

    /// The format and version first, so a newer capture is refused as one.
    pub fn read(blob: Value) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Tag {
            format: String,
            version: u32,
        }
        let not_ours = || "it is not an opCA ACME broker capture".to_string();
        let tag = Tag::deserialize(&blob).map_err(|_| not_ours())?;
        if tag.format != FORMAT || tag.version == 0 {
            return Err(not_ours());
        }
        if tag.version > VERSION {
            return Err(format!(
                "it is capture version {}, newer than this broker's {VERSION}: update the app first",
                tag.version
            ));
        }
        Self::deserialize(blob).map_err(|_| "its sections did not parse".into())
    }
}

/// A capture read and checked whole against this broker: its `acme.db` staged, and the enrolment to write.
#[derive(Default)]
struct Checked {
    inspection: AppInspection,
    acme: Option<PathBuf>,
    enrolment: Option<Enrolled>,
}

impl Broker {
    pub async fn capture(&self) -> Result<Capture, Error> {
        let _lock = self.lock().await?;
        capture_state(&self.state, Some(self.acme())).await
    }

    pub async fn inspect(&self, blob: Value) -> Result<AppInspection, ErrorBody> {
        let checked = self.check_capture(blob).await;
        discard(checked.acme.as_deref())?;
        Ok(checked.inspection)
    }

    /// All or nothing: a failure anywhere leaves `acme.db` and the enrolment as they were.
    pub async fn restore(
        self: Arc<Self>,
        body: AppRestore<Value>,
    ) -> Result<RestoreReport, ErrorBody> {
        let _lock = self.lock().await.map_err(failed)?;
        let checked = self.check_capture(body.sections).await;
        let applied = self.apply(&checked, &body.chosen).await;
        discard(checked.acme.as_deref())?;
        let applied = applied?;
        let broker = self.clone();
        tokio::task::spawn_blocking(move || broker.reload_locked())
            .await
            .map_err(failed)?
            .map_err(failed)?;
        tracing::warn!(sections = ?applied.app, "restored from a backup");
        Ok(RestoreReport {
            applied,
            warnings: checked.inspection.warnings,
            signed_out: false,
        })
    }

    async fn apply(&self, checked: &Checked, chosen: &Chosen) -> Result<Chosen, ErrorBody> {
        if !checked.inspection.blocked.is_empty() {
            let why: Vec<String> = checked
                .inspection
                .blocked
                .iter()
                .map(|(section, why)| format!("{section}: {why}"))
                .collect();
            return Err(bad_request(format!("not restored: {}", why.join("; "))));
        }
        let wanted = |section: &str| chosen.app.contains(section);
        let db = checked.acme.as_deref().filter(|_| wanted(ACME));
        let enrolment = checked.enrolment.as_ref().filter(|_| wanted(ENROLMENT));
        let path = self.enrolment_path();
        let before = match std::fs::read(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            read => Some(read.map_err(failed)?),
        };
        let mut written = false;
        let mut write_enrolment = || -> Result<(), Error> {
            if let Some(enrolment) = enrolment {
                wslib_file_atomic::replace_private(&path, &serde_json::to_vec_pretty(enrolment)?)?;
                written = true;
            }
            Ok(())
        };
        let swapped = match db {
            Some(db) => self.acme().replace_from(db, write_enrolment).await,
            None => write_enrolment(),
        };
        if let Err(error) = swapped {
            if written {
                match &before {
                    Some(before) => wslib_file_atomic::replace_private(&path, before),
                    None => std::fs::remove_file(&path),
                }
                .map_err(failed)?;
            }
            return Err(failed(error));
        }
        let app = [(ACME, db.is_some()), (ENROLMENT, enrolment.is_some())]
            .into_iter()
            .filter(|(_, restored)| *restored)
            .map(|(section, _)| section.into())
            .collect();
        Ok(Chosen {
            app,
            ..Chosen::default()
        })
    }

    async fn check_capture(&self, blob: Value) -> Checked {
        let mut checked = Checked::default();
        let inspection = &mut checked.inspection;
        let capture = match Capture::read(blob) {
            Ok(capture) => capture,
            Err(why) => {
                inspection.blocked = both_blocked(&why);
                return checked;
            }
        };
        if let Some(acme) = capture.acme {
            match self.stage_acme(acme).await {
                Ok((db, certificates)) => {
                    inspection
                        .contains
                        .app
                        .insert(ACME.into(), certificates as usize);
                    checked.acme = Some(db);
                }
                Err(why) => {
                    inspection.blocked.insert(ACME.into(), why);
                }
            }
        }
        match capture.enrolment {
            Some(enrolment) => {
                inspection.contains.app.insert(ENROLMENT.into(), 1);
                match self.enrolment_to_restore(enrolment, &mut inspection.warnings) {
                    Ok(enrolled) => checked.enrolment = enrolled,
                    Err(why) => {
                        inspection.blocked.insert(ENROLMENT.into(), why);
                    }
                }
            }
            None if matches!(self.mode(), Mode::Enrolled(_)) => inspection.warnings.push(
                "The backup was taken before enrolment, so this broker's enrolment is kept.".into(),
            ),
            None => {}
        }
        checked
    }

    /// `acme.db` decoded into the state directory and checked; its path and certificate count.
    async fn stage_acme(&self, acme: Value) -> Result<(PathBuf, u64), String> {
        let section: AcmeSection =
            serde_json::from_value(acme).map_err(|_| "its section did not parse".to_string())?;
        if section.schema > SCHEMA {
            return Err(format!(
                "its acme.db is at schema {}, newer than this broker's {SCHEMA}: update the app first",
                section.schema
            ));
        }
        let db = from_base64url(&section.db)
            .and_then(|deflated| inflate(&deflated))
            .ok_or_else(|| "its acme.db is not deflated base64url".to_string())?;
        let staged = self.state.join("restore.db");
        let counted = async {
            remove_db(&staged)
                .and_then(|()| wslib_file_atomic::replace_private(&staged, &db))
                .map_err(|e| format!("it could not be staged: {e}"))?;
            let restorable = self.acme().open_restorable(&staged).await;
            restorable.map_err(|e| e.to_string())
        };
        match counted.await {
            Ok(certificates) => Ok((staged, certificates)),
            Err(why) => {
                let _ = remove_db(&staged);
                Err(format!("its acme.db cannot be restored: {why}"))
            }
        }
    }

    /// The enrolment, if its chain certifies the key held here; on a broker
    /// not yet enrolled, one for another key is left out with a warning.
    fn enrolment_to_restore(
        &self,
        enrolment: Value,
        warnings: &mut Vec<String>,
    ) -> Result<Option<Enrolled>, String> {
        let restored: Enrolled = serde_json::from_value(enrolment)
            .map_err(|_| "its section did not parse".to_string())?;
        let subordinate = pem::certificates(&restored.chain_pem)
            .ok()
            .and_then(|chain| inspect(chain.first()?).ok())
            .ok_or_else(|| "its chain did not parse".to_string())?;
        let current = enrolment::load(&self.state).map_err(|e| e.to_string())?;
        if subordinate.spki != self.subordinate().spki() {
            if let Mode::Enrolled(_) = current {
                return Err(
                    "it is for another subordinate key than the one this broker is enrolled with"
                        .into(),
                );
            }
            warnings.push(format!(
                "The backup's enrolment is for another subordinate key than this broker holds, so \
                 it is not restored: enrol the broker with opCA again, and revoke the old \
                 subordinate, serial {}, there.",
                decimal(&subordinate.serial)
            ));
            return Ok(None);
        }
        if let Mode::Enrolled(current) = current
            && current.revoked
            && !restored.revoked
        {
            return Err(
                "this broker's subordinate is revoked, which a restore does not undo".into(),
            );
        }
        if restored.api_pin != self.pin().to_string() {
            warnings.push(
                "opCA pinned another API key than this broker serves, so it will refuse the \
                 broker until it is enrolled again."
                    .into(),
            );
        }
        Ok(Some(restored))
    }
}

/// What a broker without a host left in `state`, captured as a running one would capture it.
pub async fn capture_left(state: &Path) -> Result<Capture, Error> {
    if !state.exists() {
        return Ok(Capture::new(None, None));
    }
    let locking = state.to_owned();
    let _lock = tokio::task::spawn_blocking(move || lock_state(&locking)).await??;
    let db = state.join("acme.db");
    let acme = if db.exists() {
        Some(Store::open(&db, Arc::new(default_provider())).await?)
    } else {
        None
    };
    capture_state(state, acme.as_ref()).await
}

/// `acme`'s snapshot and the enrolment in `state`, never a key or the pairing code.
async fn capture_state(state: &Path, acme: Option<&Store>) -> Result<Capture, Error> {
    let acme = match acme {
        Some(acme) => Some(serde_json::to_value(AcmeSection {
            schema: SCHEMA,
            db: base64url(&deflate(&snapshot(state, acme).await?)?),
        })?),
        None => None,
    };
    let enrolment = match enrolment::load(state)? {
        Mode::Enrolled(enrolled) => Some(serde_json::to_value(enrolled)?),
        Mode::Enrolling => None,
    };
    Ok(Capture::new(acme, enrolment))
}

async fn snapshot(state: &Path, acme: &Store) -> Result<Vec<u8>, Error> {
    let copy = state.join("capture.db");
    remove_db(&copy)?;
    let taken = acme.snapshot(&copy, SystemTime::now()).await;
    let db = taken
        .map_err(Error::from)
        .and_then(|()| Ok(std::fs::read(&copy)?));
    remove_db(&copy)?;
    db
}

/// Whatever a capture holds, blocked for one reason.
pub fn both_blocked(why: &str) -> BTreeMap<String, String> {
    [ACME, ENROLMENT]
        .into_iter()
        .map(|section| (section.to_string(), why.to_string()))
        .collect()
}

/// Each blocked reason as a warning too: the console at ApplianceOS `5a2d0f2`
/// reads only the warnings, and restores what is blocked anyway.
pub fn warned_of_blocked(mut inspection: AppInspection) -> AppInspection {
    let mut sections: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (section, why) in &inspection.blocked {
        sections.entry(why).or_default().push(section);
    }
    let warnings: Vec<String> = sections
        .into_iter()
        .map(|(why, sections)| {
            format!(
                "This backup will not be restored ({}): {why}.",
                sections.join(", ")
            )
        })
        .collect();
    inspection.warnings.extend(warnings);
    inspection
}

fn deflate(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn inflate(deflated: &[u8]) -> Option<Vec<u8>> {
    let mut db = Vec::new();
    DeflateDecoder::new(deflated)
        .take(LARGEST_DB + 1)
        .read_to_end(&mut db)
        .ok()?;
    (db.len() as u64 <= LARGEST_DB).then_some(db)
}

/// `path` and the journal files SQLite keeps beside it.
fn remove_db(path: &Path) -> io::Result<()> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        match std::fs::remove_file(file) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            removed => removed?,
        }
    }
    Ok(())
}

fn discard(staged: Option<&Path>) -> Result<(), ErrorBody> {
    staged.map_or(Ok(()), |db| remove_db(db).map_err(failed))
}

pub(crate) fn failed(error: impl std::fmt::Display) -> ErrorBody {
    tracing::error!(%error, "the backup hook failed");
    ErrorBody {
        kind: opca_acme_api::ErrorKind::Internal,
        message: error.to_string(),
    }
}
