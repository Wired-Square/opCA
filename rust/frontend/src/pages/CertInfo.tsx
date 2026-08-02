import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { useParams, useNavigate, useSearchParams } from "@solidjs/router";
import { getCertInfo, backfillCert, unignoreCert, getCertPrivateKey, recordCertCopy } from "../api/certs";
import { certKebabItems, certLabel, rekeyAndGo, renewAndGo } from "../api/certActions";
import { getVpnProfileForCn, generateOpenVpnProfile } from "../api/openvpn";
import type { CertDetail } from "../api/types";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import { confirmPrivateKeyCopy } from "../utils/confirmPrivateKey";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import Availability from "../components/Availability";
import CopyableValue from "../components/CopyableValue";
import CertStatusBadge from "../components/CertStatusBadge";
import IgnoreCertDialog from "../components/IgnoreCertDialog";
import RevokeCertDialog from "../components/RevokeCertDialog";
import KebabMenu, { type KebabItem } from "../components/KebabMenu";
import { ActionResultBanner } from "../components/ResultBanner";
import { createActionResult } from "../utils/actionResult";
import "../styles/pages/cert-info.css";

export default function CertInfo() {
  const params = useParams();
  const navigate = useNavigate();
  // `freshFrom`/`op` are set when we land here right after a renew/rekey, to
  // surface the new cert's key + certificate and flag where it came from.
  const [searchParams] = useSearchParams();
  // Fast: load from local database immediately
  const [detail, { refetch, mutate }] = createResource(
    () => params.serial as string | undefined,
    (serial: string) => getCertInfo(serial),
  );
  const [showRevoke, setShowRevoke] = createSignal(false);
  const [acting, setActing] = createSignal<string | false>(false);
  const outcome = createActionResult();
  const label = () => certLabel({ cn: detail()?.cn, serial: params.serial as string });
  const [copied, markCopied] = createCopiedSignal();
  const [copiedKey, markKeyCopied] = createCopiedSignal();
  const [copiedChain, markChainCopied] = createCopiedSignal();
  const [copiedSan, markSanCopied] = createCopiedSignal();
  const [exportingKey, setExportingKey] = createSignal(false);
  const [backfilling, setBackfilling] = createSignal(false);
  const [showIgnore, setShowIgnore] = createSignal(false);
  const [regenerating, setRegenerating] = createSignal(false);

  // Slow: once the fast detail renders, fetch from 1Password in the background.
  // Track which serial we enriched (not a plain boolean) so navigating to the
  // new cert after a renew/rekey re-runs the backfill for that serial; the
  // mutate below keeps the serial unchanged, so it won't loop.
  let enrichedSerial: string | null = null;
  createEffect(() => {
    const d = detail();
    if (d && d.serial && enrichedSerial !== d.serial) {
      enrichedSerial = d.serial;
      setBackfilling(true);
      backfillCert(d.serial)
        .then((result) => mutate(result))
        .catch(() => {})
        .finally(() => setBackfilling(false));
    }
  });

  // After a renew/rekey of a VPN client cert, look up that CN's existing
  // profile (DB-backed, no `op` call) so we can offer a one-click regenerate.
  const [vpnProfile] = createResource(
    () => {
      const d = detail();
      if (d && searchParams.freshFrom && isVpnClient(d) && d.cn) return d.cn;
      return undefined;
    },
    (cn: string) => getVpnProfileForCn(cn),
  );

  async function handleRegenerateVpn(cn: string, template: string) {
    setRegenerating(true);
    outcome.clear();
    try {
      const profile = await generateOpenVpnProfile({
        cn,
        serial: params.serial as string,
        template_name: template,
      });
      outcome.report(`Regenerated VPN profile for ${cn} (stored as ${profile.title})`);
    } catch (e) {
      outcome.report("VPN profile regeneration failed", e);
    } finally {
      setRegenerating(false);
    }
  }

  async function handleRekey() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("rekey");
    outcome.clear();
    try {
      // Navigates to the rekeyed cert's new serial so its fresh key +
      // certificate are surfaced for copy-on-click; the DB sync runs in the
      // background.
      await rekeyAndGo(navigate, serial);
    } catch (e) {
      outcome.report("Rekey failed", e);
    } finally {
      setActing(false);
    }
  }

  async function handleRenew() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("renew");
    outcome.clear();
    try {
      await renewAndGo(navigate, serial);
    } catch (e) {
      outcome.report("Renew failed", e);
    } finally {
      setActing(false);
    }
  }

  async function handleUnignore() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("unignore");
    outcome.clear();
    try {
      await unignoreCert(serial);
      outcome.report(`Unignored ${label()}`);
      refetch();
    } catch (e) {
      outcome.report("Unignore failed", e);
    } finally {
      setActing(false);
    }
  }

  // Header actions menu — gating shared with the certificates list kebab.
  function certActions(d: CertDetail): KebabItem[] {
    return certKebabItems(d, {
      onRekey: () => void handleRekey(),
      onRenew: () => void handleRenew(),
      onRevoke: () => setShowRevoke(true),
      onIgnore: () => setShowIgnore(true),
      onUnignore: () => void handleUnignore(),
    }, !!acting());
  }

  function copyPem() {
    const pem = detail()?.cert_pem;
    const serial = params.serial as string;
    if (pem && serial) {
      void writeClipboard(pem);
      markCopied();
      void recordCertCopy("local", serial, "certificate");
    }
  }

  function copyChain() {
    const pem = detail()?.chain_pem;
    const serial = params.serial as string;
    if (pem && serial) {
      void writeClipboard(pem);
      markChainCopied();
      void recordCertCopy("local", serial, "chain");
    }
  }

  async function copyPrivateKey() {
    const serial = params.serial as string;
    if (!serial) return;
    if (!(await confirmPrivateKeyCopy(detail()?.cn ?? serial))) return;
    outcome.clear();
    setExportingKey(true);
    let key = "";
    try {
      key = await getCertPrivateKey(serial);
      await writeClipboard(key);
      markKeyCopied();
      // No recordCertCopy() call here: get_cert_private_key already audits
      // server-side via state.log_ok, and refuses CA keys outright.
    } catch (e) {
      outcome.report("Could not copy the private key", e);
    } finally {
      key = "";
      setExportingKey(false);
    }
  }

  // Until backfill finishes, we know whether a chain exists (has_chain) but
  // don't have the chain PEM in hand yet. Render the indicator as "unknown"
  // (loading) rather than green-but-broken in that window.
  function chainIndicatorState(d: CertDetail): boolean | null {
    if (d.has_chain === true && !d.chain_pem) return null;
    return d.has_chain;
  }

  function isCaCert(d: CertDetail): boolean {
    return d.cert_type?.toLowerCase() === "ca";
  }

  function isVpnClient(d: CertDetail): boolean {
    return d.cert_type?.toLowerCase() === "vpnclient";
  }

  return (
    <div class="page-cert-info">
      <div class="page-header">
        <h2>Certificate Detail</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={() => navigate("/certs")}>
            Back to list
          </button>
          <Show when={detail()}>
            {(d) => <KebabMenu items={certActions(d())} ariaLabel="Certificate actions" />}
          </Show>
        </div>
      </div>

      <div class="cert-info-scroll">
        <Show when={detail.error}>
          <p class="page-error" role="alert">{String(detail.error)}</p>
        </Show>

        <ActionResultBanner outcome={outcome} />

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
                    <NavLink class="mono superseded-link" href={`/certs/${d().superseded_by}`}>
                      serial {d().superseded_by}
                    </NavLink>
                    {" "}&mdash; the newer cert with the same Common Name is
                    Valid, so this one no longer counts toward the expired-cert
                    alert.
                  </span>
                </div>
              </Show>

              <div class="cert-info-sticky-banners">
              <Show when={searchParams.freshFrom}>
                <div class="ignored-banner fresh-banner">
                  <span class="ignored-banner-label">New certificate</span>
                  <span class="ignored-banner-body">
                    {searchParams.op === "rekey" ? "Rekeyed" : "Renewed"} from{" "}
                    <NavLink class="mono superseded-link" href={`/certs/${searchParams.freshFrom}`}>
                      serial {searchParams.freshFrom}
                    </NavLink>
                    {searchParams.op === "rekey"
                      ? " — this certificate has a new private key and certificate. Copy both below."
                      : " — a new certificate with the same private key. Copy the certificate below."}
                  </span>
                </div>
              </Show>

              <Show when={searchParams.freshFrom && isVpnClient(d())}>
                <Show
                  when={vpnProfile()}
                  fallback={
                    <Show when={!vpnProfile.loading}>
                      <div class="ignored-banner vpn-regen-banner">
                        <span class="ignored-banner-label">VPN profile</span>
                        <span class="ignored-banner-body">
                          This is a VPN client certificate with no recorded
                          profile.{" "}
                          <NavLink
                            class="superseded-link"
                            href={`/openvpn?add=1&serial=${encodeURIComponent(d().serial ?? "")}&cn=${encodeURIComponent(d().cn ?? "")}`}
                          >
                            Generate one on the OpenVPN page
                          </NavLink>
                          {" "}for <span class="mono">{d().cn}</span>.
                        </span>
                      </div>
                    </Show>
                  }
                >
                  {(profile) => (
                    <div class="ignored-banner vpn-regen-banner">
                      <span class="ignored-banner-label">VPN profile</span>
                      <span class="ignored-banner-body">
                        Regenerate <span class="mono">{profile().cn}</span>'s VPN
                        profile{" "}
                        <Show when={profile().template}>
                          (template <span class="mono">{profile().template}</span>){" "}
                        </Show>
                        to pick up the new key/certificate.
                        <div class="vpn-regen-actions">
                          <button
                            class="btn-primary btn-sm"
                            disabled={regenerating() || !profile().template}
                            onClick={() => handleRegenerateVpn(profile().cn, profile().template!)}
                          >
                            {regenerating() ? "Regenerating…" : "Regenerate VPN profile"}
                          </button>
                        </div>
                        <div class="vpn-regen-caveat">
                          Uses the stored template; verify it references the
                          current cert by CN.
                        </div>
                      </span>
                    </div>
                  )}
                </Show>
              </Show>
              </div>

              <div class="detail-grid">
                <div class="detail-row">
                  <span class="detail-label">Stored Items</span>
                  <div class="stored-items">
                    <Availability
                      label="Certificate"
                      available={d().cert_pem ? true : null}
                      onCopy={copyPem}
                      copied={copied()}
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
                <Row label="Serial" value={d().serial} mono copy />
                <Row label="Common Name" value={d().cn} copy />
                <Row label="Title" value={d().title} copy />
                <Row label="Type" value={d().cert_type} />
                <div class="detail-row">
                  <span class="detail-label">Status</span>
                  <CertStatusBadge status={d().status} expiringSoon={d().expiring_soon} />
                  <Show when={d().ignored_at}>
                    <span class="status-badge status-ignored">ignored</span>
                  </Show>
                </div>
                <Row label="Subject" value={d().subject} mono copy />
                <Row label="Issuer" value={d().issuer} mono copy />
                <Row label={<>Valid From <TzToggle /></>} value={formatDate(d().not_before)} />
                <Row label="Expiry" value={formatDate(d().expiry_date)} />
                <Row label="Revocation Date" value={formatDate(d().revocation_date)} />
                <Row label="Key Type" value={d().key_type} />
                <Row label="Key Size" value={d().key_size != null ? String(d().key_size) : null} />
                <div class="detail-row">
                  <span class="detail-label">
                    SAN
                    <Show when={sanList(d()).length > 1}>
                      <button
                        type="button"
                        class="san-copy-all"
                        title="Copy all SANs"
                        onClick={() => { void writeClipboard(d().san!); markSanCopied(); }}
                      >
                        {copiedSan() ? "Copied" : "Copy all"}
                      </button>
                    </Show>
                  </span>
                  <Show when={sanList(d()).length > 0} fallback={<span class="detail-value">{"\u2014"}</span>}>
                    <div class="san-list">
                      <For each={sanList(d())}>
                        {(name) => <CopyableValue value={name} mono />}
                      </For>
                    </div>
                  </Show>
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

              <IgnoreCertDialog
                open={showIgnore()}
                serial={d().serial}
                cn={d().cn}
                onClose={() => setShowIgnore(false)}
                onDone={() => { outcome.report(`Ignored ${label()}`); refetch(); }}
              />

              <RevokeCertDialog
                open={showRevoke()}
                serial={d().serial}
                cn={d().cn}
                onClose={() => setShowRevoke(false)}
                onDone={() => { outcome.report(`Revoked ${label()}`); refetch(); }}
              />
            </>
          )}
        </Show>
      </div>

    </div>
  );
}

/** Internal client-side navigation link (no full-page reload). */
function NavLink(props: {
  href: string;
  class?: string;
  children: import("solid-js").JSX.Element;
}) {
  const navigate = useNavigate();
  return (
    <a
      class={props.class}
      href={props.href}
      onClick={(e) => {
        e.preventDefault();
        navigate(props.href);
      }}
    >
      {props.children}
    </a>
  );
}

function Row(props: {
  label: string | import("solid-js").JSX.Element;
  value: string | null | undefined;
  mono?: boolean;
  cls?: string;
  /** When set, the value becomes a click-to-copy affordance. */
  copy?: boolean;
}) {
  return (
    <div class="detail-row">
      <span class="detail-label">{props.label}</span>
      <Show
        when={props.copy}
        fallback={
          <span class={`detail-value ${props.mono ? "mono" : ""} ${props.cls ?? ""}`}>
            {props.value ?? "\u2014"}
          </span>
        }
      >
        <CopyableValue value={props.value} mono={props.mono} />
      </Show>
    </div>
  );
}

/** Split a cert's comma-separated SAN string into trimmed, non-empty names. */
function sanList(d: CertDetail): string[] {
  return (d.san ?? "").split(",").map((s) => s.trim()).filter(Boolean);
}

