import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { useParams, useNavigate } from "@solidjs/router";
import {
  getExternalCertInfo,
  backfillExternalCert,
  getExternalCertPrivateKey,
  recordCertCopy,
} from "../api/certs";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import { confirmPrivateKeyCopy } from "../utils/confirmPrivateKey";
import type { ExternalCertDetail } from "../api/types";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import Availability from "../components/Availability";
import "../styles/pages/cert-info.css";

export default function ExternalCertInfo() {
  const params = useParams();
  const navigate = useNavigate();
  const [detail, { mutate }] = createResource(
    () => params.serial as string | undefined,
    (serial: string) => getExternalCertInfo(serial),
  );
  const [error, setError] = createSignal<string | null>(null);
  const [copiedPem, markPemCopied] = createCopiedSignal();
  const [copiedChain, markChainCopied] = createCopiedSignal();
  const [copiedKey, markKeyCopied] = createCopiedSignal();
  const [exportingKey, setExportingKey] = createSignal(false);
  const [backfilling, setBackfilling] = createSignal(false);

  let enriched = false;
  createEffect(() => {
    const d = detail();
    if (d && !enriched) {
      enriched = true;
      setBackfilling(true);
      backfillExternalCert(d.serial!)
        .then((result) => mutate(result))
        .catch(() => {})
        .finally(() => setBackfilling(false));
    }
  });

  function copyPem() {
    const pem = detail()?.cert_pem;
    const serial = params.serial as string;
    if (pem && serial) {
      void writeClipboard(pem);
      markPemCopied();
      void recordCertCopy("external", serial, "certificate");
    }
  }

  function copyChain() {
    const pem = detail()?.chain_pem;
    const serial = params.serial as string;
    if (pem && serial) {
      void writeClipboard(pem);
      markChainCopied();
      void recordCertCopy("external", serial, "chain");
    }
  }

  async function copyPrivateKey() {
    const serial = params.serial as string;
    if (!serial) return;
    if (!(await confirmPrivateKeyCopy(detail()?.cn ?? serial))) return;
    setError(null);
    setExportingKey(true);
    let key = "";
    try {
      key = await getExternalCertPrivateKey(serial);
      await writeClipboard(key);
      markKeyCopied();
      // No recordCertCopy() call here: get_external_cert_private_key already
      // audits server-side via state.log_ok, and refuses CA keys outright.
    } catch (e) {
      setError(String(e));
    } finally {
      key = "";
      setExportingKey(false);
    }
  }

  // Until backfill finishes, we know whether a chain exists (has_chain) but
  // don't have the chain PEM in hand yet. Render as "unknown" (loading) in
  // that window rather than green-but-broken.
  function chainIndicatorState(d: ExternalCertDetail): boolean | null {
    if (d.has_chain === true && !d.chain_pem) return null;
    return d.has_chain;
  }

  function isCaCert(d: ExternalCertDetail): boolean {
    return d.cert_type?.toLowerCase() === "ca";
  }

  return (
    <div class="page-cert-info">
      <div class="page-header">
        <h2>External Certificate Detail</h2>
        <button class="btn-ghost" onClick={() => navigate("/certs?tab=external")}>
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
              <div class="detail-grid">
                <Row label="Serial" value={d().serial} mono />
                <Row label="Common Name" value={d().cn} />
                <Row label="Title" value={d().title} />
                <Row label="Type" value={d().cert_type} />
                <div class="detail-row">
                  <span class="detail-label">Status</span>
                  <span class={`status-badge status-${(d().status ?? "").toLowerCase()}`}>
                    {d().status ?? "—"}
                  </span>
                </div>
                <Row label="Subject" value={d().subject} mono />
                <Row label="Issuer" value={d().issuer} mono />
                <Row label="Issuer Subject" value={d().issuer_subject} mono />
                <Row label={<>Valid From <TzToggle /></>} value={formatDate(d().not_before)} />
                <Row label="Expiry" value={formatDate(d().expiry_date)} />
                <Row label="Imported" value={formatDate(d().import_date)} />
                <Row label="Key Type" value={d().key_type} />
                <Row label="Key Size" value={d().key_size != null ? String(d().key_size) : null} />
                <div class="detail-row">
                  <span class="detail-label">SAN</span>
                  <Show when={d().san} fallback={<span class="detail-value">{"—"}</span>}>
                    <div class="san-list">
                      <For each={d().san!.split(",").map((s: string) => s.trim()).filter(Boolean)}>
                        {(name) => <span class="san-entry mono">{name}</span>}
                      </For>
                    </div>
                  </Show>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Stored Items</span>
                  <div class="stored-items">
                    <Availability
                      label="Certificate"
                      available={d().cert_pem ? true : null}
                      onCopy={copyPem}
                      copied={copiedPem()}
                    />
                    <Availability
                      label="Private Key"
                      available={d().has_private_key}
                      onCopy={isCaCert(d()) ? undefined : copyPrivateKey}
                      busy={exportingKey()}
                      copied={copiedKey()}
                      blocked={isCaCert(d())
                        ? "CA private keys cannot be copied from opCA. Retrieve from 1Password directly if absolutely necessary."
                        : undefined}
                    />
                    <Availability
                      label="Chain"
                      available={chainIndicatorState(d())}
                      onCopy={copyChain}
                      copied={copiedChain()}
                    />
                  </div>
                </div>
              </div>

              <Show when={d().cert_pem}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">Certificate PEM</span>
                  </div>
                  <pre class="pem-block">{d().cert_pem}</pre>
                </div>
              </Show>

              <Show when={d().chain_pem}>
                <div class="pem-section">
                  <div class="pem-header">
                    <span class="pem-label">Certificate Chain</span>
                  </div>
                  <pre class="pem-block">{d().chain_pem}</pre>
                </div>
              </Show>

              <Show when={error()}>
                <p class="page-error mt-3" role="alert">{error()}</p>
              </Show>
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
}) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <span class={`detail-value ${props.mono ? "mono" : ""}`}>
        {props.value ?? "—"}
      </span>
    </div>
  );
}

