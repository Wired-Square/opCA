import { For, Show, createResource, createSignal } from "solid-js";
import { Badges, Button, Confirm, DateModeToggle, NothingYet, Notice, createAction, type Tone } from "@wired-square/kit";
import {
  brokerErrorText,
  brokerStatus,
  concernText,
  listBrokers,
  renewAllBrokers,
  renewBroker,
  renewalText,
  revokeBroker,
} from "../api/brokers";
import type { BrokerRenewal, BrokerRow } from "../api/types";
import ActionMenu from "../components/ActionMenu";
import EnrolBrokerDialog from "../components/EnrolBrokerDialog";
import { ActionOutcome } from "../components/ResultBanner";
import Spinner from "../components/Spinner";
import StoredDate from "../components/StoredDate";
import { createActing, failureOf } from "../utils/acting";
import "../styles/pages/acme.css";

const brokerName = (b: BrokerRow) => b.cn ?? b.url ?? `Broker ${b.id}`;

const notDelivered = (b: BrokerRow) => b.concerns.some((c) => c.concern === "not_delivered");

export default function AcmeServers() {
  const [brokers, { refetch }] = createResource(listBrokers);
  const [enrolling, setEnrolling] = createSignal(false);
  const [revoking, setRevoking] = createSignal<BrokerRow | null>(null);
  const [outcomes, setOutcomes] = createSignal<BrokerRenewal[]>([]);
  const [report, setReport] = createSignal<{ tone: Tone; text: string } | null>(null);
  const action = createAction();

  const nameOf = (id: number) => {
    const row = brokers()?.find((b) => b.id === id);
    return row ? brokerName(row) : `Broker ${id}`;
  };

  const showOutcomes = (renewals: BrokerRenewal[]) => {
    setOutcomes(renewals);
    setReport(null);
    void refetch();
  };

  const renewOne = (id: number, changeDomains = false) =>
    action.run(
      () => renewBroker(id, changeDomains),
      (renewal) => showOutcomes([{ ...renewal, id }]),
    );

  const renewAll = () => action.run(renewAllBrokers, showOutcomes);

  const checkStatus = (id: number) =>
    action.run(
      () => brokerStatus(id),
      (s) => {
        setReport({
          tone: s.state === "issuing" ? "good" : "warn",
          text: `${nameOf(id)}: ${s.state.replace(/_/g, " ")}, serial ${s.subordinate_serial}, broker ${s.versions.broker}, step-ca ${s.versions.step_ca}`,
        });
        void refetch();
      },
    );

  const active = () => (brokers() ?? []).filter((b) => b.state === "active");

  return (
    <div class="page-acme">
      <div class="page-header">
        <h2>ACME Servers</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={() => refetch()} disabled={brokers.loading}>
            Refresh
          </button>
          <Button pending={action.pending()} disabled={active().length === 0} onClick={renewAll}>
            Renew All
          </Button>
          <Button tone="primary" onClick={() => setEnrolling(true)}>
            Enrol Broker
          </Button>
        </div>
      </div>

      <Notice tone="bad">{failureOf(brokers.error)}</Notice>
      <ActionOutcome action={action} />

      <Show when={outcomes().length > 0}>
        <div class="broker-outcomes" aria-label="Renewal outcomes">
          <For each={outcomes()}>
            {(o) => (
              <div class={`broker-outcome broker-outcome--${o.outcome === "renewed" ? "good" : "bad"}`}>
                <span class="broker-outcome-name">{nameOf(o.id)}</span>
                <span class="broker-outcome-text">{renewalText(o)}</span>
                <Show when={o.outcome === "domains_changed"}>
                  <Button tone="primary" pending={action.pending()} onClick={() => renewOne(o.id, true)}>
                    Confirm and Renew
                  </Button>
                </Show>
              </div>
            )}
          </For>
          <button class="btn-ghost btn-sm" onClick={() => setOutcomes([])}>
            Dismiss
          </button>
        </div>
      </Show>

      <Show when={report()}>{(r) => <Notice tone={r().tone}>{r().text}</Notice>}</Show>

      <Show when={brokers.loading && !brokers()}>
        <Spinner message="Loading ACME servers..." />
      </Show>

      <Show when={brokers()}>
        {(rows) => (
          <Show
            when={rows().length > 0}
            fallback={
              <NothingYet
                label="No ACME brokers yet"
                note="Install opca-acme-broker on a host, then enrol it here with the pairing string it prints."
              />
            }
          >
            <div class="data-table-wrap">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Broker</th>
                    <th>Domains</th>
                    <th>State</th>
                    <th>Subordinate Expires <DateModeToggle /></th>
                    <th>Last Contact</th>
                    <th class="kebab-col"></th>
                  </tr>
                </thead>
                <tbody>
                  <For each={rows()}>
                    {(b) => (
                      <tr class="data-table-row" classList={{ "data-table-row-ignored": b.state === "revoked" }}>
                        <td>
                          {brokerName(b)}
                          <Show when={b.cn && b.url}>
                            <span class="broker-url mono">{b.url}</span>
                          </Show>
                        </td>
                        <td>{b.permitted_domains.join(", ")}</td>
                        <td>
                          <Badges>
                            <span class={`status-badge status-${b.state}`}>{b.state}</span>
                            <Show when={notDelivered(b)}>
                              <span
                                class="status-badge status-not-delivered"
                                title="Signed, but the broker has not taken it; enrol again with the same pairing string"
                              >
                                not delivered
                              </span>
                            </Show>
                            <For each={b.concerns.filter((c) => c.concern !== "not_delivered")}>
                              {(c) => <span class={`status-badge status-${c.concern}`}>{concernText(c)}</span>}
                            </For>
                          </Badges>
                        </td>
                        <td class="mono"><StoredDate value={b.expiry_date} /></td>
                        <td class="mono"><StoredDate value={b.last_contact} /></td>
                        <td class="kebab-col">
                          <ActionMenu
                            aria-label={`Actions for ${brokerName(b)}`}
                            items={[
                              { label: "Status", onSelect: () => checkStatus(b.id), disabled: notDelivered(b) },
                              { label: "Renew", onSelect: () => renewOne(b.id), disabled: b.state !== "active" },
                              { label: "Revoke", onSelect: () => setRevoking(b), danger: true },
                            ]}
                          />
                        </td>
                      </tr>
                    )}
                  </For>
                </tbody>
              </table>
            </div>
          </Show>
        )}
      </Show>

      <EnrolBrokerDialog
        open={enrolling()}
        onClose={() => setEnrolling(false)}
        onDone={(enrolled) => {
          action.succeed(
            `Enrolled ${enrolled.broker.cn ?? enrolled.broker.url} for ${enrolled.broker.permitted_domains.join(", ")}`,
          );
          void refetch();
        }}
      />

      <RevokeBrokerDialog
        broker={revoking()}
        onClose={() => setRevoking(null)}
        onDone={(tone, text) => {
          setReport({ tone, text });
          void refetch();
        }}
      />
    </div>
  );
}

function RevokeBrokerDialog(props: {
  broker: BrokerRow | null;
  onClose: () => void;
  onDone: (tone: Tone, text: string) => void;
}) {
  const acting = createActing();
  return (
    <Show when={props.broker}>
      {(b) => (
        <Confirm
          title="Revoke Broker"
          verb={acting.verb("Revoke", "Revoking…")}
          onClose={props.onClose}
          act={acting.act(async () => {
            const revoked = await revokeBroker(b().id);
            if (revoked.notice === "told") {
              props.onDone("good", `Revoked ${brokerName(b())}; the CRL is regenerated and the broker has stopped issuing`);
            } else {
              props.onDone(
                "warn",
                `Revoked ${brokerName(b())} and regenerated the CRL, but the broker was not told: ${brokerErrorText(revoked.error)}`,
              );
            }
          })}
        >
          Revoke the subordinate CA of <span class="mono">{brokerName(b())}</span>? Its certificates stop
          being trusted once the CRL is published, and the broker stops issuing. This cannot be undone.
        </Confirm>
      )}
    </Show>
  );
}
