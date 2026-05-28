import { Show, For, createSignal, createResource, createEffect } from "solid-js";
import { useParams, useNavigate, useSearchParams } from "@solidjs/router";
import { getCertInfo, backfillCert, revokeCert, renewCert, rekeyCert, ignoreCert, unignoreCert, getCertPrivateKey, recordCertCopy } from "../api/certs";
import { getVpnProfileForCn, generateOpenVpnProfile } from "../api/openvpn";
import type { CertDetail } from "../api/types";
import { uploadDbIfPrivateStore } from "../api/ca";
import { formatDate } from "../utils/dates";
import { createCopiedSignal, writeClipboard } from "../utils/clipboard";
import { confirmPrivateKeyCopy } from "../utils/confirmPrivateKey";
import TzToggle from "../components/TzToggle";
import Spinner from "../components/Spinner";
import Availability from "../components/Availability";
import CertStatusBadge from "../components/CertStatusBadge";
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
  const [confirming, setConfirming] = createSignal(false);
  const [acting, setActing] = createSignal<string | false>(false);
  const [error, setError] = createSignal<string | null>(null);
  const [copied, markCopied] = createCopiedSignal();
  const [copiedKey, markKeyCopied] = createCopiedSignal();
  const [copiedChain, markChainCopied] = createCopiedSignal();
  const [exportingKey, setExportingKey] = createSignal(false);
  const [backfilling, setBackfilling] = createSignal(false);
  const [showIgnoreForm, setShowIgnoreForm] = createSignal(false);
  const [ignoreNote, setIgnoreNote] = createSignal("");
  const [regenerating, setRegenerating] = createSignal(false);
  const [regenMsg, setRegenMsg] = createSignal<string | null>(null);

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
    setRegenMsg(null);
    setError(null);
    try {
      const profile = await generateOpenVpnProfile({ cn, template_name: template });
      setRegenMsg(`Regenerated VPN profile for ${cn} (stored as ${profile.title}).`);
    } catch (e) {
      setError(String(e));
    } finally {
      setRegenerating(false);
    }
  }

  // After a mutating op, push the DB to the private store (if configured)
  // without prompting. Progress shows in the side-nav status; surface failures
  // on the page. Fire-and-forget so it doesn't block navigation to the new cert.
  function syncDbToPrivateStore() {
    void uploadDbIfPrivateStore().catch((e) => setError(String(e)));
  }

  async function handleRevoke() {
    const serial = params.serial as string;
    if (!serial) return;
    setActing("revoke");
    setError(null);
    try {
      await revokeCert(serial);
      setConfirming(false);
      refetch();
      syncDbToPrivateStore();
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
    try {
      const result = await rekeyCert(serial);
      // The rekeyed cert lives at a new serial — navigate there so its new key
      // + certificate are surfaced for copy-on-click; the DB sync runs in the
      // background.
      navigate(`/certs/${result.serial}?freshFrom=${serial}&op=rekey`);
      syncDbToPrivateStore();
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
    try {
      const result = await renewCert(serial);
      navigate(`/certs/${result.serial}?freshFrom=${serial}&op=renew`);
      syncDbToPrivateStore();
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
    setError(null);
    setExportingKey(true);
    let key = "";
    try {
      key = await getCertPrivateKey(serial);
      await writeClipboard(key);
      markKeyCopied();
      // No recordCertCopy() call here: get_cert_private_key already audits
      // server-side via state.log_ok, and refuses CA keys outright.
    } catch (e) {
      setError(String(e));
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
                    <NavLink class="mono superseded-link" href={`/certs/${d().superseded_by}`}>
                      serial {d().superseded_by}
                    </NavLink>
                    {" "}&mdash; the newer cert with the same Common Name is
                    Valid, so this one no longer counts toward the expired-cert
                    alert.
                  </span>
                </div>
              </Show>

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
                          <NavLink class="superseded-link" href="/openvpn">
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
                        <Show when={regenMsg()}>
                          <div class="page-success">{regenMsg()}</div>
                        </Show>
                        <div class="vpn-regen-caveat">
                          Uses the stored template; verify it references the
                          current cert by CN.
                        </div>
                      </span>
                    </div>
                  )}
                </Show>
              </Show>

              <div class="detail-grid">
                <Row label="Serial" value={d().serial} mono />
                <Row label="Common Name" value={d().cn} />
                <Row label="Title" value={d().title} />
                <Row label="Type" value={d().cert_type} />
                <div class="detail-row">
                  <span class="detail-label">Status</span>
                  <CertStatusBadge status={d().status} expiringSoon={d().expiring_soon} />
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

                <Show when={(d().status === "Expired" || d().expiring_soon) && !d().ignored_at && !d().superseded_by && !showIgnoreForm()}>
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

