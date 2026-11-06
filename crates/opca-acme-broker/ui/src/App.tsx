import { For, Match, Show, Switch, createResource, createSignal, onMount } from "solid-js";
import {
  Badge,
  Button,
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

import { issued, status } from "./api";
import type { AppState, AppStatus, IssuedCertificate, RevokedFilter } from "./api";
import { standing } from "./standing";
import type { Standing } from "./standing";

const STATES: Record<AppState, { label: string; tone: Tone }> = {
  needs_host: { label: "Needs a host", tone: "warn" },
  enrolling: { label: "Awaiting enrolment", tone: "neutral" },
  enrolled: { label: "Enrolled", tone: "good" },
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
          <Notice tone="neutral">Enrol the broker from opCA: its pairing URI is in the app's log.</Notice>
        </Match>
        <Match when={props.status.state === "revoked"}>
          <Notice tone="bad">opCA revoked the broker's subordinate, so it issues nothing more.</Notice>
        </Match>
      </Switch>
    </>
  );
}

function Url(props: { label: string; url: string | null }) {
  return (
    <Show when={props.url}>
      {(url) => (
        <>
          <dt>{props.label}</dt>
          <dd class="facts__url">{url()}</dd>
        </>
      )}
    </Show>
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
      <Td numeric>{props.certificate.serial}</Td>
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
