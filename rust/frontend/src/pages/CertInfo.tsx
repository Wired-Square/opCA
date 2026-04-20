import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { useParams, useNavigate } from "@solidjs/router";
import { getCertInfo, backfillCert, revokeCert, renewCert, rekeyCert, ignoreCert, unignoreCert } from "../api/certs";
import { getCaConfig, uploadCaDatabase } from "../api/ca";
import { formatDate } from "../utils/dates";
import { createCopiedSignal } from "../utils/clipboard";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import "../styles/pages/cert-info.css";

export default function CertInfo() {
  const params = useParams();
  const navigate = useNavigate();
  // Fast: load from local database immediately
  const [detail, { refetch, mutate }] = createResource(
    () => params.serial as string | undefined,
    (serial: string) => getCertInfo(serial),
  );
  const [confirming, setConfirming] = createSignal(false);
  const [acting, setActing] = createSignal<string | false>(false);
  const [error, setError] = createSignal<string | null>(null);
  const [copied, markCopied] = createCopiedSignal();
  const [backfilling, setBackfilling] = createSignal(false);
  const [showUploadPrompt, setShowUploadPrompt] = createSignal(false);
  const [uploadingDb, setUploadingDb] = createSignal(false);
  const [showIgnoreForm, setShowIgnoreForm] = createSignal(false);
  const [ignoreNote, setIgnoreNote] = createSignal("");

  // Slow: once the fast detail renders, fetch from 1Password in the background.
  // Use a plain boolean to avoid re-triggering the effect on mutate.
  let enriched = false;
  createEffect(() => {
    const d = detail();
    if (d && !enriched) {
      enriched = true;
      setBackfilling(true);
      backfillCert(d.serial!)
        .then((result) => mutate(result))
        .catch(() => {})
        .finally(() => setBackfilling(false));
    }
  });

  async function maybeShowUploadPrompt() {
    try {
      const config = await getCaConfig();
      if (config.ca_private_store) {
        setShowUploadPrompt(true);
      }
    } catch {
      // Ignore — just don't show the prompt
    }
  }

  async function handleUploadDb() {
    setUploadingDb(true);
    try {
      await uploadCaDatabase();
      setShowUploadPrompt(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setUploadingDb(false);
    }
  }

  async function handleRevoke() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("revoke");
    setError(null);
    setShowUploadPrompt(false);
    try {
      await revokeCert(serial);
      setConfirming(false);
      refetch();
      await maybeShowUploadPrompt();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleRekey() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("rekey");
    setError(null);
    setShowUploadPrompt(false);
    try {
      await rekeyCert(serial);
      refetch();
      await maybeShowUploadPrompt();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleRenew() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("renew");
    setError(null);
    setShowUploadPrompt(false);
    try {
      await renewCert(serial);
      refetch();
      await maybeShowUploadPrompt();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleIgnore() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("ignore");
    setError(null);
    try {
      const note = ignoreNote().trim() || undefined;
      await ignoreCert(serial, note);
      setShowIgnoreForm(false);
      setIgnoreNote("");
      refetch();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  async function handleUnignore() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("unignore");
    setError(null);
    try {
      await unignoreCert(serial);
      refetch();
    } catch (e) {
      setError(String(e));
    } finally {
      setActing(false);
    }
  }

  function copyPem() {
    const pem = detail()?.cert_pem;
    if (pem) {
      navigator.clipboard.writeText(pem);
      markCopied();
    }
  }

  return (
    <div class="page-cert-info">
      <div class="page-header">
        <h2>Certificate Detail</h2>
        <button class="btn-ghost" onClick={() => navigate("/certs")}>
          Back to list
        </button>
      </div>

      <div class="cert-info-scroll">
        <Show when={detail.error}>
          <p class="page-error" role="alert">{String(detail.error)}</p>
        </Show>

        <Show when={detail.loading}>
          <Spinner message="Loading…" />
        </Show>

        <Show when={backfilling()}>
          <Spinner message="Fetching details from vault…" />
        </Show>

        <Show when={detail()}>
          {(d) => (
            <>
              <Show when={d().ignored_at}>
                <div class="ignored-banner">
                  <span class="ignored-banner-label">Ignored</span>
                  <span class="ignored-banner-body">
                    {d().ignored_reason ?? "manual"}
                    <Show when={d().ignored_by}>
                      {" "}by <span class="mono">{d().ignored_by}</span>
                    </Show>
                    <Show when={d().ignored_at}>
                      {" "}on <span class="mono">{formatDate(d().ignored_at)}</span> <TzToggle />
                    </Show>
                    <Show when={d().ignored_note}>
                      {" "}&mdash; <span>{d().ignored_note}</span>
                    </Show>
                  </span>
                </div>
              </Show>

              <Show when={d().superseded_by && !d().ignored_at}>
                <div class="ignored-banner superseded-banner">
                  <span class="ignored-banner-label">Superseded</span>
                  <span class="ignored-banner-body">
                    Replaced by{" "}
                    <a
                      class="mono superseded-link"
                      href={`/certs/${d().superseded_by}`}
                      onClick={(e) => {
                        e.preventDefault();
                        navigate(`/certs/${d().superseded_by}`);
                      }}
                    >
                      serial {d().superseded_by}
                    </a>
                    {" "}&mdash; the newer cert with the same Common Name is
                    Valid, so this one no longer counts toward the expired-cert
                    alert.
                  </span>
                </div>
              </Show>

              <div class="detail-grid">
                <Row label="Serial" value={d().serial} mono />
                <Row label="Common Name" value={d().cn} />
                <Row label="Title" value={d().title} />
                <Row label="Type" value={d().cert_type} />
                <div class="detail-row">
                  <span class="detail-label">Status</span>
                  <span class={`status-badge status-${(d().status ?? "").toLowerCase()}`}>
                    {d().status ?? "\u2014"}
                  </span>
                  <Show when={d().ignored_at}>
                    <span class="status-badge status-ignored">ignored</span>
                  </Show>
                </div>
                <Row label="Subject" value={d().subject} mono />
                <Row label="Issuer" value={d().issuer} mono />
                <Row label={<>Valid From <TzToggle /></>} value={formatDate(d().not_before)} />
                <Row label="Expiry" value={formatDate(d().expiry_date)} />
                <Row label="Revocation Date" value={formatDate(d().revocation_date)} />
                <Row label="Key Type" value={d().key_type} />
                <Row label="Key Size" value={d().key_size != null ? String(d().key_size) : null} />
                <div class="detail-row">
                  <span class="detail-label">SAN</span>
                  <Show when={d().san} fallback={<span class="detail-value">{"\u2014"}</span>}>
                    <div class="san-list">
                      <For each={d().san!.split(",").map((s: string) => s.trim()).filter(Boolean)}>
                        {(name) => <span class="san-entry mono">{name}</span>}
                      </For>
                    </div>
                  </Show>
                </div>
              </div>

              <Show when={d().cert_pem}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">Certificate PEM</span>
                    <button class="btn-ghost btn-sm" onClick={copyPem}>
                      {copied() ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre class="pem-block">{d().cert_pem}</pre>
                </div>
              </Show>

              <Show when={showUploadPrompt()}>
                <div class="upload-prompt">
                  <span>Upload database to private store?</span>
                  <div class="upload-actions">
                    <button class="btn-primary btn-sm" onClick={handleUploadDb} disabled={uploadingDb()}>
                      {uploadingDb() ? "Uploading\u2026" : "Upload"}
                    </button>
                    <button class="btn-ghost btn-sm" onClick={() => setShowUploadPrompt(false)}>
                      Dismiss
                    </button>
                  </div>
                </div>
              </Show>

              <Show when={error()}>
                <p class="page-error mt-3" role="alert">{error()}</p>
              </Show>

              <div class="cert-actions">
                <Show when={!acting() || acting() === "rekey"}>
                  <button class="btn-primary" onClick={handleRekey} disabled={!!acting()}>
                    {acting() === "rekey" ? "Rekeying…" : "Rekey"}
                  </button>
                </Show>
                <Show when={d().status === "Valid"}>
                  <Show when={!acting() || acting() === "renew"}>
                    <button class="btn-primary" onClick={handleRenew} disabled={!!acting()}>
                      {acting() === "renew" ? "Renewing…" : "Renew"}
                    </button>
                  </Show>
                  <Show when={!acting() && !confirming()}>
                    <button class="btn-danger" onClick={() => setConfirming(true)}>
                      Revoke
                    </button>
                  </Show>
                  <Show when={confirming()}>
                    <Show when={!acting() || acting() === "revoke"}>
                      <div class="confirm-inline">
                        <Show when={!acting()}>
                          <span class="text-warning">Are you sure?</span>
                        </Show>
                        <button class="btn-danger" onClick={handleRevoke} disabled={!!acting()}>
                          {acting() === "revoke" ? "Revoking…" : "Confirm Revoke"}
                        </button>
                        <Show when={!acting()}>
                          <button class="btn-ghost" onClick={() => setConfirming(false)}>
                            Cancel
                          </button>
                        </Show>
                      </div>
                    </Show>
                  </Show>
                </Show>

                <Show when={d().status === "Expired" && !d().ignored_at && !d().superseded_by && !showIgnoreForm()}>
                  <button class="btn-ghost" onClick={() => setShowIgnoreForm(true)} disabled={!!acting()}>
                    Ignore
                  </button>
                </Show>

                <Show when={showIgnoreForm() && !d().ignored_at}>
                  <div class="confirm-inline ignore-inline">
                    <input
                      type="text"
                      class="ignore-note-input"
                      value={ignoreNote()}
                      onInput={(e) => setIgnoreNote(e.currentTarget.value)}
                      placeholder={"Optional note \u2014 why?"}
                      disabled={!!acting()}
                      autofocus
                    />
                    <button class="btn-primary" onClick={handleIgnore} disabled={!!acting()}>
                      {acting() === "ignore" ? "Ignoring\u2026" : "Confirm Ignore"}
                    </button>
                    <Show when={!acting()}>
                      <button
                        class="btn-ghost"
                        onClick={() => { setShowIgnoreForm(false); setIgnoreNote(""); }}
                      >
                        Cancel
                      </button>
                    </Show>
                  </div>
                </Show>

                <Show when={d().ignored_at}>
                  <button class="btn-ghost" onClick={handleUnignore} disabled={!!acting()}>
                    {acting() === "unignore" ? "Un-ignoring\u2026" : "Un-ignore"}
                  </button>
                </Show>
              </div>
            </>
          )}
        </Show>
      </div>

    </div>
  );
}

function Row(props: {
  label: string | import("solid-js").JSX.Element;
  value: string | null | undefined;
  mono?: boolean;
  cls?: string;
}) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <span class={`detail-value ${props.mono ? "mono" : ""} ${props.cls ?? ""}`}>
        {props.value ?? "\u2014"}
      </span>
    </div>
  );
}
