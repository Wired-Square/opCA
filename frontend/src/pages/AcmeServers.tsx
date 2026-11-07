import { For, Show, createResource, createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { Button, DateModeToggle, NothingYet, Notice } from "@wired-square/kit";
import { listBrokerCerts, listBrokers, renewAllBrokers } from "../api/brokers";
import ActionMenu from "../components/ActionMenu";
import { BrokerBadges, brokerName, createBrokerControls, issuedText } from "../components/BrokerControls";
import EnrolBrokerDialog from "../components/EnrolBrokerDialog";
import Spinner from "../components/Spinner";
import StoredDate from "../components/StoredDate";
import { onBrokersSynced } from "../stores/brokerSync";
import { failureOf } from "../utils/acting";
import "../styles/pages/acme.css";

export default function AcmeServers() {
  const navigate = useNavigate();
  const [brokers, { refetch: refetchBrokers }] = createResource(listBrokers);
  const [certs, { refetch: refetchCerts }] = createResource(listBrokerCerts);
  const [enrolling, setEnrolling] = createSignal(false);

  const refetch = () => {
    void refetchBrokers();
    void refetchCerts();
  };
  onBrokersSynced(refetch);

  const certsOf = (id: number) => (certs() ?? []).filter((c) => c.broker_id === id);

  const nameOf = (id: number) => {
    const row = brokers()?.find((b) => b.id === id);
    return row ? brokerName(row) : `Broker ${id}`;
  };

  const controls = createBrokerControls({ nameOf, refetch });

  const active = () => (brokers() ?? []).filter((b) => b.state === "active");

  return (
    <div class="page-acme">
      <div class="page-header">
        <h2>ACME Servers</h2>
        <div class="header-actions">
          <button class="btn-ghost" onClick={() => refetch()} disabled={brokers.loading}>
            Refresh
          </button>
          <Button
            pending={controls.action.pending()}
            disabled={active().length === 0}
            onClick={() => controls.action.run(renewAllBrokers, controls.showOutcomes)}
          >
            Renew All
          </Button>
          <Button tone="primary" onClick={() => setEnrolling(true)}>
            Enrol Broker
          </Button>
        </div>
      </div>

      <Notice tone="bad">{failureOf(brokers.error)}</Notice>
      <controls.Feedback />

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
                    <th>Issued</th>
                    <th class="kebab-col"></th>
                  </tr>
                </thead>
                <tbody>
                  <For each={rows()}>
                    {(b) => (
                      <tr
                        class="data-table-row"
                        classList={{ "data-table-row-ignored": b.state === "revoked" }}
                        onClick={() => navigate(`/acme/${b.id}`)}
                      >
                        <td>
                          {brokerName(b)}
                          <Show when={b.cn && b.url}>
                            <span class="broker-url mono">{b.url}</span>
                          </Show>
                        </td>
                        <td>{b.permitted_domains.join(", ")}</td>
                        <td>
                          <BrokerBadges broker={b} />
                        </td>
                        <td class="mono"><StoredDate value={b.expiry_date} /></td>
                        <td class="mono"><StoredDate value={b.last_contact} /></td>
                        <td>
                          <Show when={certsOf(b.id).length > 0} fallback="—">
                            {issuedText(certsOf(b.id).length, certsOf(b.id).filter((c) => c.revoked_at).length)}
                          </Show>
                        </td>
                        <td class="kebab-col" onClick={(e) => e.stopPropagation()}>
                          <ActionMenu aria-label={`Actions for ${brokerName(b)}`} items={controls.items(b)} />
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
          controls.action.succeed(
            `Enrolled ${enrolled.broker.cn ?? enrolled.broker.url} for ${enrolled.broker.permitted_domains.join(", ")}`,
          );
          refetch();
        }}
      />
    </div>
  );
}
