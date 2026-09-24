import { Show, createEffect, createResource, createSignal } from "solid-js";
import { errorMessage } from "../api/tauri";
import {
  getCrlInfo,
  backfillCrl,
  generateCrl,
  uploadCrl,
  inspectCrl,
  recordCrlCopy,
} from "../api/crl";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import Availability from "../components/Availability";
import { ActionResultBanner } from "../components/ResultBanner";
import UploadPrompt from "../components/UploadPrompt";
import PageError from "../components/PageError";
import { createActionResult } from "../utils/actionResult";
import { createAction } from "../utils/action";
import { createPublishFlow } from "../utils/publishFlow";
import type { CrlInfo, InspectCrlResult } from "../api/types";
import "../styles/pages/crl.css";

type Tab = "detail" | "inspect";

export default function CRL() {
  const [info, { refetch, mutate }] = createResource<CrlInfo>(getCrlInfo);
  const [tab, setTab] = createSignal<Tab>("detail");
  const outcome = createActionResult();
  const generate = createAction(outcome);
  const publish = createPublishFlow({
    upload: uploadCrl,
    success: "CRL uploaded to public store",
    outcome,
  });
  const [copied, markCopied] = createCopiedSignal();
  const [backfilling, setBackfilling] = createSignal(false);

  const [inspectPem, setInspectPem] = createSignal("");
  const [inspecting, setInspecting] = createSignal(false);
  const [inspectError, setInspectError] = createSignal<string | null>(null);
  const [inspectResult, setInspectResult] = createSignal<InspectCrlResult | null>(null);
  const [inspectCopied, markInspectCopied] = createCopiedSignal();

  // Slow path: load the actual CRL PEM in the background after the fast
  // metadata-only fetch lands. Same pattern as CertInfo.
  let enriched = false;
  createEffect(() => {
    const d = info();
    if (d && !enriched) {
      enriched = true;
      setBackfilling(true);
      backfillCrl()
        .then((result) => {
          mutate(result);
          // Prefill the Inspect tab with the live CRL so the user can
          // decode what's actually published without copy/paste gymnastics.
          if (result.crl_pem) setInspectPem(result.crl_pem);
        })
        .catch(() => {})
        .finally(() => setBackfilling(false));
    }
  });

  function handleGenerate() {
    publish.dismiss();
    return generate.run(
      { success: (crl) => `CRL #${crl.crl_number ?? "?"} generated`, failure: "Generate failed" },
      async () => {
        const generated = await generateCrl();
        mutate(generated);
        if (generated.crl_pem) setInspectPem(generated.crl_pem);
        setInspectResult(null);
        if (generated.has_public_store) publish.offer();
        return generated;
      },
    );
  }

  function copyPem() {
    const pem = info()?.crl_pem;
    if (pem) {
      void writeClipboard(pem);
      markCopied();
      void recordCrlCopy();
    }
  }

  async function handleInspect() {
    const pem = inspectPem().trim();
    setInspectError(null);
    setInspectResult(null);
    if (!pem) {
      setInspectError("CRL PEM is required.");
      return;
    }
    setInspecting(true);
    try {
      const result = await inspectCrl(pem);
      setInspectResult(result);
    } catch (e) {
      setInspectError(errorMessage(e));
    } finally {
      setInspecting(false);
    }
  }

  function copyInspectDump() {
    const dump = inspectResult()?.text_dump;
    if (dump) {
      void writeClipboard(dump);
      markInspectCopied();
    }
  }

  return (
    <div class="page-crl">
      <div class="page-header">
        <h2>Certificate Revocation List</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={() => { enriched = false; refetch(); }} disabled={info.loading || backfilling()}>
            {info.loading ? "Loading…" : "Refresh"}
          </button>
          <Show when={info()?.has_public_store}>
            <button class="btn-ghost" onClick={publish.handleUpload} disabled={publish.uploading()}>
              {publish.uploading() ? "Uploading…" : "Upload CRL"}
            </button>
          </Show>
          <button class="btn-primary" onClick={handleGenerate} disabled={generate.busy()}>
            {generate.busy() ? "Generating…" : "Generate CRL"}
          </button>
        </div>
      </div>

      <div class="tab-bar">
        <button
          class={`tab-btn ${tab() === "detail" ? "tab-active" : ""}`}
          onClick={() => setTab("detail")}
        >
          Detail
        </button>
        <button
          class={`tab-btn ${tab() === "inspect" ? "tab-active" : ""}`}
          onClick={() => setTab("inspect")}
        >
          Inspect
        </button>
      </div>

      <div class="crl-scroll">
        <UploadPrompt flow={publish} message="Upload CRL to public store?" />

        <ActionResultBanner outcome={outcome} />

        <PageError message={info.error} />

        <Show when={info.loading}>
          <Spinner message="Loading…" />
        </Show>

        <Show when={tab() === "detail" && info()}>
          {(d) => (
            <>
              <Show when={backfilling()}>
                <Spinner message="Loading CRL from vault…" />
              </Show>

              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Issuer</span>
                  <span class="detail-value mono">{d().issuer ?? "—"}</span>
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
                  <span class="detail-value">{d().crl_number ?? "—"}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Revoked Certificates</span>
                  <span class="detail-value">{d().revoked_count}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Stored Items</span>
                  <div class="stored-items">
                    <Availability
                      label="CRL Document"
                      available={d().crl_pem ? true : d().has_crl}
                      onCopy={copyPem}
                      copied={copied()}
                    />
                  </div>
                </div>
              </div>

              <Show when={d().crl_pem}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">CRL PEM</span>
                  </div>
                  <pre class="pem-block">{d().crl_pem}</pre>
                </div>
              </Show>
            </>
          )}
        </Show>

        <Show when={tab() === "inspect"}>
          <div class="form-group">
            <label class="form-label">CRL PEM</label>
            <textarea
              rows={10}
              placeholder="Paste CRL PEM here, or leave the live CRL prefilled…"
              value={inspectPem()}
              onInput={(e) => {
                setInspectPem(e.currentTarget.value);
                setInspectResult(null);
                setInspectError(null);
              }}
              autocomplete="off"
              autocorrect="off"
              autocapitalize="off"
              spellcheck={false}
            />
          </div>

          <div class="form-actions">
            <button
              class="btn-primary"
              type="button"
              disabled={inspecting() || !inspectPem().trim()}
              onClick={handleInspect}
            >
              {inspecting() ? "Inspecting…" : "Inspect CRL"}
            </button>
          </div>

          <PageError message={inspectError()} />

          <Show when={inspectResult()}>
            {(r) => (
              <div class="detail-section">
                <div class="detail-grid">
                  <div class="detail-row">
                    <span class="detail-label">Issuer</span>
                    <span class="detail-value mono">{r().issuer || "—"}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">Last Update <TzToggle /></span>
                    <span class="detail-value mono">{formatDate(r().last_update)}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">Next Update</span>
                    <span class="detail-value mono">{formatDate(r().next_update)}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">CRL Number</span>
                    <span class="detail-value">{r().crl_number ?? "—"}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">Revoked Certificates</span>
                    <span class="detail-value">{r().revoked_count}</span>
                  </div>
                  <div class="detail-row">
                    <span class="detail-label">Signature Algorithm</span>
                    <span class="detail-value mono">{r().signature_algorithm}</span>
                  </div>
                </div>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">Text Dump</span>
                    <button
                      type="button"
                      class="btn-ghost btn-sm"
                      onClick={copyInspectDump}
                    >
                      {inspectCopied() ? "Copied" : "Copy"}
                    </button>
                  </div>
                  <pre class="text-dump mono">{r().text_dump}</pre>
                </div>
              </div>
            )}
          </Show>
        </Show>
      </div>

    </div>
  );
}
