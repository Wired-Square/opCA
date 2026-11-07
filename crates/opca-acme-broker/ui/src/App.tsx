import { For, Match, Show, Switch, createResource, createSignal, onMount } from "solid-js";
import {
  Badge,
  Button,
  Confirm,
  CopyButton,
  Loaded,
  Notice,
  NothingYet,
  Section,
  Select,
  Table,
  Td,
  Th,
  Tr,
  createPagedList,
} from "@wired-square/kit";
import type { Tone } from "@wired-square/kit";
import { day, when } from "@wired-square/kit/core";
import { useAllows } from "@wired-square/appliance-ui";

import { issued, newPairing, status } from "./api";
import type { AppState, AppStatus, IssuedCertificate, RevokedFilter } from "./api";
import { pairingView } from "./pairing";
import { hexSerial } from "./serial";
import { standing } from "./standing";
import type { Standing } from "./standing";

const STATES: Record<AppState, { label: string; tone: Tone }> = {
  needs_host: { label: "Needs a host", tone: "warn" },
  enrolling: { label: "Awaiting enrolment", tone: "neutral" },
  enrolled: { label: "Enrolled", tone: "good" },
  paused: { label: "Paused", tone: "warn" },
  revoked: { label: "Revoked", tone: "bad" },
};

const STANDINGS: Record<Standing["kind"], Tone> = {
  valid: "good",
  expiring: "warn",
  expired: "neutral",
  revoked: "bad",
};

const FILTERS: Record<string, RevokedFilter> = { all: null, unrevoked: false, revoked: true };

export function App() {
  const [broker, { refetch }] = createResource(status);
  return (
    <>
      <Loaded of={broker} refetch={refetch} reading="the broker's status">
        {(broker) => <Status status={broker()} />}
      </Loaded>
      <Issued />
    </>
  );
}

function Status(props: { status: AppStatus }) {
  const state = () => STATES[props.status.state];
  return (
    <>
      <dl class="facts">
        <dt>State</dt>
        <dd>
          <Badge tone={state().tone}>{state().label}</Badge>
        </dd>
        <dt>Host</dt>
        <dd>{props.status.host ?? "—"}</dd>
        <Url label="API" url={props.status.api_url} />
        <Url label="ACME directory" url={props.status.acme_directory} />
        <Url label="CA certificate" url={props.status.ca_url} />
        <Url label="CRL" url={props.status.crl_url} />
        <Show when={props.status.crl}>
          {(crl) => (
            <>
              <dt>CRL updated</dt>
              <dd>{when(crl().this_update)}</dd>
              <dt>CRL next update</dt>
              <dd>{when(crl().next_update)}</dd>
            </>
          )}
        </Show>
        <dt>Domains</dt>
        <dd>{props.status.domains.join(", ") || "chosen in opCA"}</dd>
        <Show when={props.status.subordinate}>
          {(subordinate) => (
            <>
              <dt>Subordinate</dt>
              <dd class="facts__serial">{subordinate().serial}</dd>
              <dt>Subordinate expires</dt>
              <dd title={when(subordinate().not_after)}>{day(subordinate().not_after)}</dd>
            </>
          )}
        </Show>
      </dl>
      <Switch>
        <Match when={props.status.state === "needs_host"}>
          <Notice tone="warn">Set the app's host option in the console, and the broker starts.</Notice>
        </Match>
        <Match when={props.status.state === "enrolling"}>
          <Pairing />
        </Match>
        <Match when={props.status.state === "paused"}>
          <Notice tone="warn">
            opCA paused issuance, so ACME clients can't order or renew certificates until it resumes. Revocation,
            the CRL and the subordinate's renewal carry on.
          </Notice>
        </Match>
        <Match when={props.status.state === "revoked"}>
          <Notice tone="bad">opCA revoked the broker's subordinate, so it issues nothing more.</Notice>
        </Match>
      </Switch>
    </>
  );
}

function Pairing() {
  const allows = useAllows();
  const [uri, setUri] = createSignal<string | null>(null);
  const [revealed, setRevealed] = createSignal(false);
  const [confirming, setConfirming] = createSignal(false);
  const view = () => pairingView(allows("admin"), uri(), revealed());
  const issued = () => {
    const shown = view();
    return shown.kind === "issued" ? shown : undefined;
  };
  const issue = async () => {
    setUri((await newPairing()).uri);
    setRevealed(false);
  };

  return (
    <Section
      title="Pairing"
      blurb="Enrol the broker from opCA with a pairing URI. A new URI cancels the one before it."
    >
      <Show
        when={view().kind !== "ask_an_admin"}
        fallback={<Notice tone="neutral">An admin can issue a pairing URI from this page.</Notice>}
      >
        <Show when={issued()}>
          {(issued) => (
            <div class="pairing">
              <code class="pairing__uri">{issued().shown}</code>
              <Button onClick={() => setRevealed(!issued().revealed)}>{issued().revealed ? "Hide" : "Reveal"}</Button>
              <CopyButton value={issued().uri}>Copy</CopyButton>
            </div>
          )}
        </Show>
        <Button onClick={() => setConfirming(true)}>New pairing URI</Button>
        <Show when={confirming()}>
          <Confirm
            title="New pairing URI"
            verb="Issue it"
            tone="primary"
            act={issue}
            onClose={() => setConfirming(false)}
          >
            This cancels any pairing URI already handed out, the one in the app's log among them. The new one is shown
            only until this page is reloaded.
          </Confirm>
        </Show>
      </Show>
    </Section>
  );
}

function Url(props: { label: string; url: string | null }) {
  return (
    <>
      <dt>{props.label}</dt>
      <dd class="facts__url">{props.url ?? "—"}</dd>
    </>
  );
}

function Issued() {
  const [filter, setFilter] = createSignal("all");
  const list = createPagedList<IssuedCertificate, number>(async (before) => {
    const page = await issued(FILTERS[filter()], before);
    return { items: page.certificates, next: page.before };
  }, "serial");
  onMount(() => void list.refresh());
  const now = Date.now();

  return (
    <Section
      title="Issued certificates"
      blurb="Newest first. Revoke them in opCA."
      actions={
        <Select
          label="Show"
          value={filter()}
          onValue={(chosen) => {
            setFilter(chosen);
            void list.refresh();
          }}
        >
          <option value="all">All</option>
          <option value="unrevoked">Not revoked</option>
          <option value="revoked">Revoked</option>
        </Select>
      }
    >
      <Notice tone="bad">{list.failed()}</Notice>
      <Show
        when={list.rows().length > 0}
        fallback={
          <Show when={list.started()}>
            <NothingYet label="Nothing issued yet" />
          </Show>
        }
      >
        <Table
          head={
            <>
              <Th>Common name</Th>
              <Th>SANs</Th>
              <Th>Serial</Th>
              <Th>Not before</Th>
              <Th>Not after</Th>
              <Th>Status</Th>
            </>
          }
        >
          <For each={list.rows()}>{(certificate) => <Row certificate={certificate} now={now} />}</For>
        </Table>
      </Show>
      <Show when={list.hasMore()}>
        <Button pending={list.pending()} onClick={() => void list.more()}>
          Show older
        </Button>
      </Show>
    </Section>
  );
}

function Row(props: { certificate: IssuedCertificate; now: number }) {
  const held = () => standing(props.certificate, props.now);
  return (
    <Tr dim={held().kind === "expired" || held().kind === "revoked"}>
      <Td strong>{props.certificate.common_name ?? "—"}</Td>
      <Td>{props.certificate.sans.join(", ")}</Td>
      <Td numeric>{hexSerial(props.certificate.serial)}</Td>
      <Td numeric>
        <span title={when(props.certificate.not_before)}>{day(props.certificate.not_before)}</span>
      </Td>
      <Td numeric>
        <span title={when(props.certificate.not_after)}>{day(props.certificate.not_after)}</span>
      </Td>
      <Td>
        <StandingBadge standing={held()} />
      </Td>
    </Tr>
  );
}

function StandingBadge(props: { standing: Standing }) {
  return (
    <>
      <Badge tone={STANDINGS[props.standing.kind]}>{props.standing.kind}</Badge>
      <Show when={props.standing.kind === "revoked" && props.standing.reason}>
        {(reason) => <span class="reason">{reason()}</span>}
      </Show>
    </>
  );
}
