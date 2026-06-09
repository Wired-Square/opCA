import { Show } from "solid-js";

/** Primary status badge for a certificate: an orange badge when the cert is
 * inside the expiry-warning window, otherwise the status-coloured badge. The
 * colour follows the status/expiry; `label`, when given, overrides the badge
 * text (e.g. a serial like "#28") while keeping that colour — used by the VPN
 * client picker. Ignored/superseded chips are rendered separately by each
 * caller, since the list and detail views surface them differently. */
export default function CertStatusBadge(props: {
  status: string | null;
  expiringSoon: boolean;
  label?: string;
}) {
  return (
    <Show
      when={props.expiringSoon}
      fallback={
        <span class={`status-badge status-${(props.status ?? "").toLowerCase()}`}>
          {props.label ?? props.status ?? "—"}
        </span>
      }
    >
      <span class="status-badge status-expiring">
        {props.label ?? "Expiring Soon"}
      </span>
    </Show>
  );
}
