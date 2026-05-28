import { Show } from "solid-js";

/** Primary status badge for a certificate: an orange "Expiring Soon" badge when
 * the cert is inside the expiry-warning window, otherwise the status-coloured
 * badge. Ignored/superseded chips are rendered separately by each caller, since
 * the list and detail views surface them differently. */
export default function CertStatusBadge(props: {
  status: string | null;
  expiringSoon: boolean;
}) {
  return (
    <Show
      when={props.expiringSoon}
      fallback={
        <span class={`status-badge status-${(props.status ?? "").toLowerCase()}`}>
          {props.status ?? "—"}
        </span>
      }
    >
      <span class="status-badge status-expiring">Expiring Soon</span>
    </Show>
  );
}
