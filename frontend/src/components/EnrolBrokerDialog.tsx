import { For, Show, createSignal } from "solid-js";
import { Button, Dialog, DialogActions, Notice, TextArea, createAction } from "@wired-square/kit";
import { domainList, enrolBroker, fetchBrokerOffer } from "../api/brokers";
import type { BrokerOffer, EnrolledBroker } from "../api/types";

interface EnrolBrokerDialogProps {
  open: boolean;
  onClose: () => void;
  onDone: (enrolled: EnrolledBroker) => void;
}

/** Paste a broker's pairing string, review what it asks for, then sign and hand it over. */
export default function EnrolBrokerDialog(props: EnrolBrokerDialogProps) {
  return (
    <Show when={props.open}>
      <EnrolBroker onClose={props.onClose} onDone={props.onDone} />
    </Show>
  );
}

function EnrolBroker(props: Omit<EnrolBrokerDialogProps, "open">) {
  const [pairing, setPairing] = createSignal("");
  const [offered, setOffered] = createSignal<BrokerOffer | null>(null);
  const [domains, setDomains] = createSignal("");
  const action = createAction();

  const brokerDomains = () => offered()?.offer.configured_domains ?? [];
  const chosen = () => (brokerDomains().length > 0 ? [] : domainList(domains()));
  const ready = () => brokerDomains().length > 0 || chosen().length > 0;

  const review = () =>
    action.run(() => fetchBrokerOffer(pairing().trim()), setOffered);

  const enrol = (offer: BrokerOffer) =>
    action.run(
      () => enrolBroker({ pairing: pairing().trim(), offer: offer.offer, domains: chosen() }),
      (enrolled) => {
        props.onDone(enrolled);
        props.onClose();
      },
    );

  return (
    <Dialog title="Enrol ACME Broker" wide pending={action.pending()} onClose={props.onClose}>
      <Notice tone="bad">{action.failed()}</Notice>
      <Show
        when={offered()}
        fallback={
          <>
            <TextArea
              label="Pairing string"
              hint="As the broker printed it: opca-enrol://host:port#pin=…&code=…"
              rows={3}
              autofocus
              spellcheck={false}
              value={pairing()}
              disabled={action.pending()}
              onValue={setPairing}
            />
            <DialogActions
              onCancel={props.onClose}
              pending={action.pending()}
              confirm={
                <Button tone="primary" pending={action.pending()} disabled={!pairing().trim()} onClick={review}>
                  Review
                </Button>
              }
            />
          </>
        }
      >
        {(o) => (
          <>
            <div class="detail-grid enrol-offer">
              <div class="detail-row">
                <span class="detail-label">Host</span>
                <span class="detail-value mono">{o().offer.host}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">Address</span>
                <span class="detail-value mono">{o().address}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">Key (SHA-256)</span>
                <span class="detail-value mono">{o().pin}</span>
              </div>
              <div class="detail-row">
                <span class="detail-label">Broker</span>
                <span class="detail-value">
                  {o().offer.versions.broker}, step-ca {o().offer.versions.step_ca}
                </span>
              </div>
            </div>
            <Show
              when={brokerDomains().length > 0}
              fallback={
                <TextArea
                  label="Permitted domains"
                  hint="One per line. Each covers itself and every name below it; the broker's host must be within one."
                  rows={3}
                  spellcheck={false}
                  value={domains()}
                  disabled={action.pending()}
                  onValue={setDomains}
                />
              }
            >
              <div class="form-group">
                <span class="form-label">Permitted domains</span>
                <ul class="enrol-domains">
                  <For each={brokerDomains()}>{(d) => <li class="mono">{d}</li>}</For>
                </ul>
                <p class="form-hint">Set on the broker; change them there, not in opCA.</p>
              </div>
            </Show>
            <DialogActions
              onCancel={props.onClose}
              pending={action.pending()}
              confirm={
                <Button tone="primary" pending={action.pending()} disabled={!ready()} onClick={() => enrol(o())}>
                  Sign and Enrol
                </Button>
              }
            />
          </>
        )}
      </Show>
    </Dialog>
  );
}
