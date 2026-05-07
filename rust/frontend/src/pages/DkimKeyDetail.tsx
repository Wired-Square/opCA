import { Show, createSignal, createResource, createEffect } from "solid-js";
import { useParams, useNavigate } from "@solidjs/router";
import {
  getDkimInfo,
  backfillDkim,
  getDkimPrivateKey,
  recordDkimCopy,
  verifyDkimDns,
  deployDkimRoute53,
  deleteDkimKey,
} from "../api/dkim";
import { formatDate } from "../utils/dates";
import { createCopiedSignal } from "../utils/clipboard";
import { confirmPrivateKeyCopy } from "../utils/confirmPrivateKey";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import Availability from "../components/Availability";
import type { DkimKeyDetail, DkimVerifyResult } from "../api/types";
import "../styles/pages/cert-info.css";
import "../styles/pages/dkim.css";

export default function DkimKeyDetailPage() {
  const params = useParams<{ domain: string; selector: string }>();
  const navigate = useNavigate();

  const [detail, { mutate, refetch }] = createResource(
    () => ({ domain: params.domain, selector: params.selector }),
    ({ domain, selector }) => getDkimInfo(domain, selector),
  );

  const [error, setError] = createSignal<string | null>(null);
  const [success, setSuccess] = createSignal<string | null>(null);
  const [backfilling, setBackfilling] = createSignal(false);
  const [verifying, setVerifying] = createSignal(false);
  const [deploying, setDeploying] = createSignal(false);
  const [confirmDelete, setConfirmDelete] = createSignal(false);
  const [deleting, setDeleting] = createSignal(false);
  const [verifyMismatch, setVerifyMismatch] = createSignal<{ expected: string; found: string } | null>(null);

  const [chunked, setChunked] = createSignal(false);
  const [exportingKey, setExportingKey] = createSignal(false);

  const [copiedSelector, markSelectorCopied] = createCopiedSignal();
  const [copiedPublicKey, markPublicKeyCopied] = createCopiedSignal();
  const [copiedDnsRecord, markDnsRecordCopied] = createCopiedSignal();
  const [copiedKey, markKeyCopied] = createCopiedSignal();

  let enriched = false;
  createEffect(() => {
    const d = detail();
    if (d && !enriched) {
      enriched = true;
      setBackfilling(true);
      backfillDkim(d.domain, d.selector)
        .then((result) => mutate(result))
        .catch(() => {})
        .finally(() => setBackfilling(false));
    }
  });

  function copySelector() {
    const d = detail();
    if (!d) return;
    const value = `${d.selector}._domainkey`;
    navigator.clipboard.writeText(value);
    markSelectorCopied();
    void recordDkimCopy(d.domain, d.selector, "selector");
  }

  function copyPublicKey() {
    const d = detail();
    if (!d?.public_key) return;
    navigator.clipboard.writeText(d.public_key);
    markPublicKeyCopied();
    void recordDkimCopy(d.domain, d.selector, "public_key");
  }

  function copyDnsRecord() {
    const d = detail();
    if (!d) return;
    const value = chunked() ? d.dns_record_chunked ?? d.dns_record : d.dns_record;
    if (!value) return;
    navigator.clipboard.writeText(value);
    markDnsRecordCopied();
    void recordDkimCopy(d.domain, d.selector, "dns_record");
  }

  async function copyPrivateKey() {
    const d = detail();
    if (!d) return;
    const label = `${d.selector}._domainkey.${d.domain}`;
    if (!(await confirmPrivateKeyCopy(label))) return;

    setError(null);
    setExportingKey(true);
    let key = "";
    try {
      key = await getDkimPrivateKey(d.domain, d.selector);
      await navigator.clipboard.writeText(key);
      markKeyCopied();
      // No recordDkimCopy() call here: get_dkim_private_key already audits
      // server-side via state.log_ok.
    } catch (e) {
      setError(String(e));
    } finally {
      key = "";
      setExportingKey(false);
    }
  }

  async function handleVerify() {
    const d = detail();
    if (!d) return;
    setVerifying(true);
    setError(null);
    setSuccess(null);
    setVerifyMismatch(null);
    try {
      const result: DkimVerifyResult = await verifyDkimDns(d.domain, d.selector);
      if (result.verified) {
        setSuccess(result.message);
      } else {
        setError(result.message);
        if (result.expected && result.found) {
          setVerifyMismatch({ expected: result.expected, found: result.found });
        }
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setVerifying(false);
    }
  }

  async function handleDeploy() {
    const d = detail();
    if (!d) return;
    setDeploying(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await deployDkimRoute53(d.domain, d.selector);
      setSuccess(result.message);
    } catch (e) {
      setError(String(e));
    } finally {
      setDeploying(false);
    }
  }

  async function handleDelete() {
    const d = detail();
    if (!d) return;
    setDeleting(true);
    setError(null);
    try {
      await deleteDkimKey(d.domain, d.selector);
      navigate("/dkim");
    } catch (e) {
      setError(String(e));
    } finally {
      setDeleting(false);
    }
  }

  function pairStatusLabel(d: DkimKeyDetail): string {
    if (d.key_pair_match === true) return "Matched";
    if (d.key_pair_match === false) return "Mismatch";
    return "—";
  }

  function pairStatusClass(d: DkimKeyDetail): string {
    if (d.key_pair_match === true) return "status-badge status-valid";
    if (d.key_pair_match === false) return "status-badge status-invalid";
    return "";
  }

  return (
    <div class="page-cert-info">
      <div class="page-header">
        <h2>DKIM Key Detail</h2>
        <button class="btn-ghost" onClick={() => navigate("/dkim")}>
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
          <Spinner message="Loading key from vault…" />
        </Show>

        <Show when={detail()}>
          {(d) => (
            <>
              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Domain</span>
                  <span class="detail-value">{d().domain}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Selector</span>
                  <span class="detail-value mono">{d().selector}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">DNS Name</span>
                  <div class="dns-name-row">
                    <Availability
                      label={`${d().selector}._domainkey`}
                      available={true}
                      onCopy={copySelector}
                      copied={copiedSelector()}
                    />
                    <span class="dns-name-suffix mono">.{d().domain}</span>
                  </div>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Key Size</span>
                  <span class="detail-value">{d().key_size != null ? `${d().key_size} bits` : "—"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Created <TzToggle /></span>
                  <span class="detail-value mono">{formatDate(d().created_at)}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Key Pair</span>
                  <span class={pairStatusClass(d())}>{pairStatusLabel(d())}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Stored Items</span>
                  <div class="stored-items">
                    <Availability
                      label="Public Key"
                      available={d().has_public_key}
                      onCopy={copyPublicKey}
                      copied={copiedPublicKey()}
                    />
                    <Availability
                      label="Private Key"
                      available={d().has_private_key}
                      onCopy={copyPrivateKey}
                      busy={exportingKey()}
                      copied={copiedKey()}
                    />
                    <Availability
                      label={chunked() ? "DNS Record (Chunked)" : "DNS Record"}
                      available={d().has_dns_record}
                      onCopy={copyDnsRecord}
                      copied={copiedDnsRecord()}
                    />
                  </div>
                </div>
              </div>

              <Show when={d().dns_record}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">DNS Record</span>
                    <button
                      class="btn-ghost btn-sm"
                      onClick={() => setChunked((v) => !v)}
                      title="Format as 255-byte chunks for AWS Route53"
                      aria-pressed={chunked()}
                    >
                      {chunked() ? "Single" : "AWS chunks"}
                    </button>
                  </div>
                  <pre class="pem-block">
                    {chunked() ? d().dns_record_chunked ?? d().dns_record : d().dns_record}
                  </pre>
                </div>
              </Show>

              <Show when={d().public_key}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">Public Key PEM</span>
                  </div>
                  <pre class="pem-block">{d().public_key}</pre>
                </div>
              </Show>

              <Show when={error()}>
                <p class="page-error mt-3" role="alert">{error()}</p>
              </Show>

              <Show when={success()}>
                <p class="page-success mt-3">{success()}</p>
              </Show>

              <Show when={verifyMismatch()}>
                {(m) => (
                  <div class="verify-mismatch">
                    <div class="mismatch-row">
                      <span class="detail-label">Expected</span>
                      <pre class="dns-record mono">{m().expected}</pre>
                    </div>
                    <div class="mismatch-row">
                      <span class="detail-label">Found</span>
                      <pre class="dns-record mono">{m().found}</pre>
                    </div>
                  </div>
                )}
              </Show>

              <div class="cert-actions">
                <button
                  class="btn-secondary"
                  onClick={handleVerify}
                  disabled={verifying() || deploying()}
                >
                  {verifying() ? "Verifying…" : "Verify DNS"}
                </button>
                <button
                  class="btn-secondary"
                  onClick={handleDeploy}
                  disabled={verifying() || deploying()}
                >
                  {deploying() ? "Deploying…" : "Deploy to Route53"}
                </button>
                <button class="btn-ghost" onClick={() => { enriched = false; refetch(); }}>
                  Refresh
                </button>
                <Show when={!confirmDelete()}>
                  <button class="btn-danger" onClick={() => setConfirmDelete(true)} disabled={deleting()}>
                    Delete
                  </button>
                </Show>
                <Show when={confirmDelete()}>
                  <span class="text-warning">Are you sure?</span>
                  <button class="btn-danger" onClick={handleDelete} disabled={deleting()}>
                    {deleting() ? "Deleting…" : "Confirm Delete"}
                  </button>
                  <button class="btn-ghost" onClick={() => setConfirmDelete(false)}>
                    Cancel
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
