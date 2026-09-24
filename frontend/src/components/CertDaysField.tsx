import { Show, createEffect, createResource, createSignal, createUniqueId, on } from "solid-js";
import { getCaConfig } from "../api/ca";
import { appleTlsLimitWarning, defaultCertDays } from "../api/types";

export type CertDays = ReturnType<typeof createCertDays>;

/** A lifetime prefilled from the CA's days for `certType`, reset when the type changes;
 * `days()` is undefined when blank, leaving the backend default. */
export function createCertDays(certType: () => string) {
  const [config] = createResource(() => getCaConfig().catch(() => null));
  const [entered, setEntered] = createSignal<string | null>(null);
  createEffect(on(certType, () => setEntered(null), { defer: true }));

  const defaultDays = () => {
    const caDays = config()?.days;
    return caDays ? defaultCertDays(certType(), caDays) : undefined;
  };
  const text = () => entered() ?? String(defaultDays() ?? "");
  const days = () => parseInt(text()) || undefined;

  return { certType, defaultDays, text, setEntered, days };
}

export default function CertDaysField(props: { state: CertDays }) {
  const id = createUniqueId();
  const warning = () => appleTlsLimitWarning(props.state.certType(), props.state.days());
  return (
    <div class="form-group">
      <label class="form-label" for={id}>Validity (days)</label>
      <input
        id={id}
        type="number"
        min="1"
        placeholder={String(props.state.defaultDays() ?? "")}
        value={props.state.text()}
        onInput={(e) => props.state.setEntered(e.currentTarget.value)}
      />
      <Show when={warning()}>
        <p class="form-hint is-warning" role="status">{warning()}</p>
      </Show>
    </div>
  );
}
