import { For, Show, createSignal } from "solid-js";
import { Badges, Button, Confirm, Notice, createAction, type Tone } from "@wired-square/kit";
import {
  brokerErrorText,
  brokerStatus,
  concernText,
  pauseBroker,
  renewBroker,
  renewalText,
  revokeBroker,
} from "../api/brokers";
import type { Broker, BrokerRenewal, BrokerRow, BrokerStatus } from "../api/types";
import type { MenuAction } from "./ActionMenu";
import { ActionOutcome } from "./ResultBanner";
import { createActing } from "../utils/acting";

export const brokerName = (b: Broker) => b.cn ?? b.url ?? `Broker ${b.id}`;

export const notDelivered = (b: BrokerRow) => b.concerns.some((c) => c.concern === "not_delivered");

export const issuedText = (total: number, revoked: number) =>
  revoked > 0 ? `${total} issued, ${revoked} revoked` : `${total} issued`;

const statusText = (s: BrokerStatus) =>
  [
    s.state.replace(/_/g, " "),
    `serial ${s.subordinate_serial}`,
    `broker ${s.versions.broker}`,
    ...(s.issued ? [issuedText(s.issued.total, s.issued.revoked)] : []),
  ].join(", ");

export function BrokerBadges(props: { broker: BrokerRow }) {
  return (
    <Badges>
      <span class={`status-badge status-${props.broker.state}`}>{props.broker.state}</span>
      <Show when={notDelivered(props.broker)}>
        <span
          class="status-badge status-not-delivered"
          title="Signed, but the broker has not taken it; enrol again with the same pairing string"
        >
          not delivered
        </span>
      </Show>
      <For each={props.broker.concerns.filter((c) => c.concern !== "not_delivered")}>
        {(c) => <span class={`status-badge status-${c.concern}`}>{concernText(c)}</span>}
      </For>
    </Badges>
  );
}

/** A broker's actions and what they report, shared by the list and a broker's own page. */
export function createBrokerControls(props: { nameOf: (id: number) => string; refetch: () => void }) {
  const action = createAction();
  const [outcomes, setOutcomes] = createSignal<BrokerRenewal[]>([]);
  const [report, setReport] = createSignal<{ tone: Tone; text: string } | null>(null);
  const [revoking, setRevoking] = createSignal<BrokerRow | null>(null);

  const say = (tone: Tone, text: string) => setReport({ tone, text });

  const showOutcomes = (renewals: BrokerRenewal[]) => {
    setOutcomes(renewals);
    setReport(null);
    props.refetch();
  };

  const renewOne = (id: number, changeDomains = false) =>
    action.run(
      () => renewBroker(id, changeDomains),
      (renewal) => showOutcomes([{ ...renewal, id }]),
    );

  const reportStatus = (b: BrokerRow) => (s: BrokerStatus) => {
    say(s.state === "issuing" ? "good" : "warn", `${brokerName(b)}: ${statusText(s)}`);
    props.refetch();
  };

  const pause = (b: BrokerRow, paused: boolean) => action.run(() => pauseBroker(b.id, paused), reportStatus(b));

  const items = (b: BrokerRow): MenuAction[] => [
    { label: "Status", onSelect: () => action.run(() => brokerStatus(b.id), reportStatus(b)), disabled: notDelivered(b) },
    { label: "Renew", onSelect: () => renewOne(b.id), disabled: b.state !== "active" },
    b.issuer_state === "paused"
      ? { label: "Resume", onSelect: () => pause(b, false), disabled: b.state !== "active" }
      : { label: "Pause", onSelect: () => pause(b, true), disabled: b.state !== "active" || notDelivered(b) },
    { label: "Revoke", onSelect: () => setRevoking(b), danger: true },
  ];

  const Feedback = () => (
    <>
      <ActionOutcome action={action} />

      <Show when={outcomes().length > 0}>
        <div class="broker-outcomes" aria-label="Renewal outcomes">
          <For each={outcomes()}>
            {(o) => (
              <div class={`broker-outcome broker-outcome--${o.outcome === "renewed" ? "good" : "bad"}`}>
                <span class="broker-outcome-name">{props.nameOf(o.id)}</span>
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

      <RevokeBrokerDialog
        broker={revoking()}
        onClose={() => setRevoking(null)}
        onDone={(tone, text) => {
          say(tone, text);
          props.refetch();
        }}
      />
    </>
  );

  return { action, items, say, showOutcomes, Feedback };
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
