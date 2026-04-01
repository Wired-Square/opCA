import { Show, createSignal, createResource } from "solid-js";
import { getCrlInfo, generateCrl, uploadCrl } from "../api/crl";
import { formatDate } from "../utils/dates";
import { createCopiedSignal } from "../utils/clipboard";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import type { CrlInfo } from "../api/types";
import "../styles/pages/crl.css";

export default function CRL() {
  const [info, { refetch, mutate }] = createResource<CrlInfo>(getCrlInfo);
  const [generating, setGenerating] = createSignal(false);
  const [uploading, setUploading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [copied, markCopied] = createCopiedSignal();
  const [showUploadPrompt, setShowUploadPrompt] = createSignal(false);

  async function handleGenerate() {
    setGenerating(true);
    setError(null);
    setShowUploadPrompt(false);
    try {
      const result = await generateCrl();
      mutate(result);
      if (result.has_public_store) {
        setShowUploadPrompt(true);
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setGenerating(false);
    }
  }

  async function handleUpload() {
    setUploading(true);
    setError(null);
    try {
      await uploadCrl();
      setShowUploadPrompt(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setUploading(false);
    }
  }

  function copyPem() {
    const pem = info()?.crl_pem;
    if (pem) {
      navigator.clipboard.writeText(pem);
      markCopied();
    }
  }

  return (
    <div class="page-crl">
      <div class="page-header">
        <h2>Certificate Revocation List</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={() => refetch()} disabled={info.loading}>
            {info.loading ? "Loading\u2026" : "Refresh"}
          </button>
          <Show when={info()?.has_public_store}>
            <button class="btn-ghost" onClick={handleUpload} disabled={uploading()}>
              {uploading() ? "Uploading\u2026" : "Upload CRL"}
            </button>
          </Show>
          <button class="btn-primary" onClick={handleGenerate} disabled={generating()}>
            {generating() ? "Generating\u2026" : "Generate CRL"}
          </button>
        </div>
      </div>

      <div class="crl-scroll">
        <Show when={showUploadPrompt()}>
          <div class="upload-prompt">
            <span>Upload CRL to public store?</span>
            <div class="upload-actions">
              <button class="btn-primary btn-sm" onClick={handleUpload} disabled={uploading()}>
                {uploading() ? "Uploading\u2026" : "Upload"}
              </button>
              <button class="btn-ghost btn-sm" onClick={() => setShowUploadPrompt(false)}>
                Dismiss
              </button>
            </div>
          </div>
        </Show>

        <Show when={info.error}>
          <p class="page-error" role="alert">{String(info.error)}</p>
        </Show>

        <Show when={error()}>
          <p class="page-error" role="alert">{error()}</p>
        </Show>

        <Show when={info.loading}>
          <Spinner message="Loading…" />
        </Show>

        <Show when={info()}>
          {(d) => (
            <>
              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Issuer</span>
                  <span class="detail-value mono">{d().issuer ?? "\u2014"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Last Update <TzToggle /></span>
                  <span class="detail-value mono">{formatDate(d().last_update)}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Next Update</span>
                  <span class="detail-value mono">{formatDate(d().next_update)}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">CRL Number</span>
                  <span class="detail-value">{d().crl_number ?? "\u2014"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Revoked Certificates</span>
                  <span class="detail-value">{d().revoked_count}</span>
                </div>
              </div>

              <Show when={d().crl_pem}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">CRL PEM</span>
                    <button class="btn-ghost btn-sm" onClick={copyPem}>
                      {copied() ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre class="pem-block">{d().crl_pem}</pre>
                </div>
              </Show>
            </>
          )}
        </Show>
      </div>

    </div>
  );
}
