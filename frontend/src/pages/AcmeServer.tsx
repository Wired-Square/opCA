import { For, Show, createResource, createSignal } from "solid-js";
import { useNavigate, useParams } from "@solidjs/router";
import { Confirm, DateModeToggle, NothingYet, Notice, Select } from "@wired-square/kit";
import { REVOCATION_REASONS, listBrokerCerts, listBrokers, revokeBrokerCert } from "../api/brokers";
import type { BrokerCert, BrokerRow } from "../api/types";
import ActionMenu from "../components/ActionMenu";
import { BrokerBadges, brokerName, createBrokerControls, issuedText } from "../components/BrokerControls";
import Spinner from "../components/Spinner";
import StoredDate from "../components/StoredDate";
import { createActing, failureOf } from "../utils/acting";
import { asn1Date } from "../utils/dates";
import "../styles/pages/acme.css";

const certState = (c: BrokerCert) => {
  if (c.revoked_at) return "revoked";
  const expiry = asn1Date(c.not_after);
  return expiry && expiry.getTime() < Date.now() ? "expired" : "valid";
};

const certName = (c: BrokerCert) => c.common_name ?? c.sans[0];

const otherSans = (c: BrokerCert) => c.sans.filter((name) => name !== certName(c));

export default function AcmeServer() {
  const params = useParams();
  const navigate = useNavigate();
  const id = () => Number(params.id);
  const [brokers, { refetch: refetchBrokers }] = createResource(listBrokers);
  const [certs, { refetch: refetchCerts }] = createResource(listBrokerCerts);
  const [revokingCert, setRevokingCert] = createSignal<BrokerCert | null>(null);

  const refetch = () => {
    void refetchBrokers();
    void refetchCerts();
  };

  const broker = () => brokers()?.find((b) => b.id === id());
  const issued = () => (certs() ?? []).filter((c) => c.broker_id === id());
  const name = () => {
    const b = broker();
    return b ? brokerName(b) : `Broker ${id()}`;
  };

  const controls = createBrokerControls({ nameOf: name, refetch });

  return (
    <div class="page-acme">
      <div class="page-header">
        <h2>{name()}</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={() => navigate("/acme")}>
            Back to list
          </button>
          <Show when={broker()}>
            {(b) => <ActionMenu aria-label={`Actions for ${brokerName(b())}`} items={controls.items(b())} />}
          </Show>
        </div>
      </div>

      <Notice tone="bad">{failureOf(brokers.error ?? certs.error)}</Notice>
      <controls.Feedback />

      <Show when={brokers.loading && !brokers()}>
        <Spinner message="Loading the ACME server..." />
      </Show>

      <Show when={brokers()}>
        <Show when={broker()} fallback={<NothingYet label="No such ACME server" note="It may have been removed." />}>
          {(b) => (
            <>
              <BrokerSummary broker={b()} issued={issued()} />
              <h3 class="section-heading">Issued Certificates</h3>
              <Show when={issued().length > 0} fallback={<p class="text-muted">Nothing issued yet.</p>}>
                <IssuedTable
                  name={brokerName(b())}
                  certs={issued()}
                  revocable={b().state === "active"}
                  onRevoke={setRevokingCert}
                />
              </Show>
            </>
          )}
        </Show>
      </Show>

      <RevokeBrokerCertDialog
        cert={revokingCert()}
        brokerName={name()}
        onClose={() => setRevokingCert(null)}
        onDone={(text) => {
          controls.say("good", text);
          void refetchCerts();
        }}
      />
    </div>
  );
}

function BrokerSummary(props: { broker: BrokerRow; issued: BrokerCert[] }) {
  return (
    <div class="detail-grid">
      <div class="detail-row">
        <span class="detail-label">URL</span>
        <span class="detail-value mono">{props.broker.url}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Domains</span>
        <span class="detail-value">{props.broker.permitted_domains.join(", ")}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">State</span>
        <BrokerBadges broker={props.broker} />
      </div>
      <div class="detail-row">
        <span class="detail-label">Subordinate Expires</span>
        <span class="detail-value mono">
          <StoredDate value={props.broker.expiry_date} /> <DateModeToggle />
        </span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Last Contact</span>
        <span class="detail-value mono">
          <StoredDate value={props.broker.last_contact} />
        </span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Issued</span>
        <span class="detail-value">
          {issuedText(props.issued.length, props.issued.filter((c) => c.revoked_at).length)}
        </span>
      </div>
    </div>
  );
}

/** Right-clicking a row opens its menu, which also sits behind the row's ⋮. */
const openRowMenu = (e: MouseEvent & { currentTarget: HTMLElement }) => {
  e.preventDefault();
  e.currentTarget.querySelector<HTMLButtonElement>(".app-menu__trigger")?.click();
};

function IssuedTable(props: {
  name: string;
  certs: BrokerCert[];
  revocable: boolean;
  onRevoke: (cert: BrokerCert) => void;
}) {
  return (
    <table class="broker-issued" aria-label={`Certificates issued by ${props.name}`}>
      <thead>
        <tr>
          <th>Certificate</th>
          <th>Expires</th>
          <th>State</th>
          <th class="kebab-col"></th>
        </tr>
      </thead>
      <tbody>
        <For each={props.certs}>
          {(c) => (
            <tr onContextMenu={openRowMenu}>
              <td>
                {certName(c)}
                <Show when={otherSans(c).length > 0}>
                  <span class="broker-sans mono">{otherSans(c).join(", ")}</span>
                </Show>
              </td>
              <td class="mono"><StoredDate value={c.not_after} /></td>
              <td>
                <span class={`status-badge status-${certState(c)}`}>{certState(c)}</span>
              </td>
              <td class="kebab-col">
                <ActionMenu
                  aria-label={`Actions for ${certName(c)}`}
                  items={[
                    {
                      label: "Revoke…",
                      onSelect: () => props.onRevoke(c),
                      disabled: !props.revocable || certState(c) !== "valid",
                      danger: true,
                    },
                  ]}
                />
              </td>
            </tr>
          )}
        </For>
      </tbody>
    </table>
  );
}

function RevokeBrokerCertDialog(props: {
  cert: BrokerCert | null;
  brokerName: string;
  onClose: () => void;
  onDone: (text: string) => void;
}) {
  const acting = createActing();
  const [reason, setReason] = createSignal("0");
  return (
    <Show when={props.cert}>
      {(c) => (
        <Confirm
          title="Revoke Certificate"
          verb={acting.verb("Revoke", "Revoking…")}
          onClose={() => {
            setReason("0");
            props.onClose();
          }}
          act={acting.act(async () => {
            await revokeBrokerCert(c().broker_id, c().serial, Number(reason()));
            props.onDone(`${props.brokerName} revoked ${certName(c())} and published it on its CRL`);
          })}
        >
          <p>
            Have <span class="mono">{props.brokerName}</span> revoke <span class="mono">{certName(c())}</span>? It
            goes on the broker's CRL at once. This cannot be undone.
          </p>
          <Select label="Reason" value={reason()} onValue={setReason}>
            <For each={REVOCATION_REASONS}>{([code, name]) => <option value={code}>{name}</option>}</For>
          </Select>
        </Confirm>
      )}
    </Show>
  );
}
