import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { useParams, useNavigate } from "@solidjs/router";
import { getCertInfo, backfillCert, revokeCert, renewCert, rekeyCert } from "../api/certs";
import { getCaConfig, uploadCaDatabase } from "../api/ca";
import { formatDate } from "../utils/dates";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";

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
  const [copied, setCopied] = createSignal(false);
  const [backfilling, setBackfilling] = createSignal(false);
  const [showUploadPrompt, setShowUploadPrompt] = createSignal(false);
  const [uploadingDb, setUploadingDb] = createSignal(false);

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

  function copyPem() {
    const pem = detail()?.cert_pem;
    if (pem) {
      navigator.clipboard.writeText(pem);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
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
          <p class="page-error">{String(detail.error)}</p>
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
                <p class="page-error" style={{ "margin-top": "16px" }}>{error()}</p>
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
              </div>
            </>
          )}
        </Show>
      </div>

      <style>{`
        .page-cert-info {
          padding: 32px;
          display: flex;
          flex-direction: column;
          height: 100%;
          box-sizing: border-box;
        }

        .page-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 24px;
          flex-shrink: 0;
        }

        .page-header h2 {
          margin: 0;
        }

        .cert-info-scroll {
          flex: 1;
          min-height: 0;
          overflow-y: auto;
        }

        .page-error {
          color: var(--error);
          font-size: 0.875rem;
          padding: 8px 12px;
          background: rgba(255, 69, 58, 0.1);
          border-radius: 6px;
          margin-bottom: 16px;
        }

        .status-badge {
          display: inline-block;
          padding: 4px 14px;
          font-size: 0.8125rem;
          font-weight: 600;
          border-radius: 20px;
          letter-spacing: 0.02em;
        }

        .status-valid {
          color: #22c55e;
          background: rgba(34, 197, 94, 0.12);
          border: 1px solid rgba(34, 197, 94, 0.3);
        }

        .status-expired,
        .status-revoked {
          color: #ef4444;
          background: rgba(239, 68, 68, 0.12);
          border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .status-expiring {
          color: #eab308;
          background: rgba(234, 179, 8, 0.12);
          border: 1px solid rgba(234, 179, 8, 0.3);
        }

        .detail-grid {
          display: grid;
          gap: 12px;
        }

        .detail-row {
          display: flex;
          gap: 16px;
          padding: 8px 12px;
          border-radius: 6px;
        }

        .detail-row:nth-child(odd) {
          background: var(--bg-elevated);
        }

        .detail-label {
          min-width: 140px;
          font-size: 0.8125rem;
          font-weight: 500;
          color: var(--text-secondary);
        }

        .detail-value {
          font-size: 0.875rem;
          color: var(--text-primary);
          word-break: break-all;
        }

        .san-list {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .san-entry {
          font-size: 0.875rem;
          color: var(--text-primary);
        }

        .pem-section {
          margin-top: 24px;
        }

        .pem-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          margin-bottom: 8px;
        }

        .pem-label {
          font-size: 0.8125rem;
          font-weight: 500;
          color: var(--text-secondary);
        }

        .pem-block {
          padding: 16px;
          background: var(--bg-elevated);
          border: 1px solid var(--border);
          border-radius: 8px;
          font-family: "SF Mono", "Cascadia Code", "Fira Code", monospace;
          font-size: 0.75rem;
          line-height: 1.5;
          overflow-x: auto;
          white-space: pre-wrap;
          word-break: break-all;
        }

        .upload-prompt {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 10px 14px;
          background: rgba(255, 149, 0, 0.1);
          border: 1px solid rgba(255, 149, 0, 0.3);
          border-radius: 8px;
          margin-top: 16px;
          font-size: 0.875rem;
          font-weight: 500;
          color: var(--text-primary);
        }

        .upload-actions {
          display: flex;
          gap: 8px;
        }

        .cert-actions {
          display: flex;
          align-items: center;
          gap: 12px;
          margin-top: 24px;
        }

        .confirm-inline {
          display: flex;
          align-items: center;
          gap: 8px;
        }

        .btn-danger {
          padding: 8px 16px;
          background: var(--error);
          color: white;
          border: none;
          border-radius: 8px;
          font-weight: 600;
          cursor: pointer;
          font-size: 0.875rem;
        }

        .btn-danger:hover {
          opacity: 0.9;
        }

        .btn-danger:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }

        .btn-sm {
          padding: 4px 10px;
          font-size: 0.75rem;
        }
      `}</style>
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
