import { Show, For, createSignal, createMemo } from "solid-js";
import CertStatusBadge from "./CertStatusBadge";
import Spinner from "./Spinner";
import { formatDate } from "../utils/dates";
import type { CertListItem } from "../api/types";
import "../styles/components/vpn-client-picker.css";

interface VpnClientPickerProps {
  /** Currently selected CN. */
  value: string;
  /** Serial of the selected cert — pins the selection to the exact cert when
   * duplicates share a CN (and lets the caller pre-fill a specific cert). */
  serial: string | null;
  /** Valid vpnclient certificates to choose from. */
  clients: CertListItem[];
  loading: boolean;
  /** Called with the selected certificate's CN and serial. */
  onChange: (cn: string, serial: string | null) => void;
}

/** A single row: coloured serial badge (green = valid, orange = expiring soon)
 * prefix, then the CN, with the expiry date right-aligned. Shared by the trigger
 * (selected cert) and the dropdown list. */
function ClientRow(props: { cert: CertListItem }) {
  return (
    <>
      <CertStatusBadge
        status={props.cert.status}
        expiringSoon={props.cert.expiring_soon}
        label={`#${props.cert.serial ?? "?"}`}
      />
      <span class="vpn-picker-cn">{props.cert.cn ?? "—"}</span>
      <span class="vpn-picker-expiry">{formatDate(props.cert.expiry_date)}</span>
    </>
  );
}

/**
 * Dropdown for choosing a VPN client certificate. Unlike a native <select> it
 * renders a coloured serial badge plus the expiry date per row, so renewal
 * duplicates — two valid certs sharing a CN — can be told apart. Selection sets
 * the CN; profile generation is CN-keyed, so the serial badge is informational.
 */
export default function VpnClientPicker(props: VpnClientPickerProps) {
  const [open, setOpen] = createSignal(false);

  // The cert backing the selection — match the exact serial the parent holds,
  // else the first match for the CN (the current, highest-serial cert, since the
  // list is sorted serial-desc within a CN). Read from props.clients so it stays
  // fresh, and so an externally pre-filled serial selects the right row.
  const selectedCert = createMemo(
    () =>
      props.clients.find((c) => c.serial === props.serial && c.cn === props.value)
      ?? props.clients.find((c) => c.cn === props.value)
      ?? null,
  );

  function select(cert: CertListItem) {
    props.onChange(cert.cn ?? "", cert.serial);
    setOpen(false);
  }

  return (
    <div class="vpn-picker">
      <button
        type="button"
        class="form-select vpn-picker-trigger"
        onClick={() => setOpen((o) => !o)}
      >
        <Show
          when={selectedCert()}
          fallback={
            <span class="vpn-picker-placeholder">Select VPN certificate</span>
          }
        >
          {(cert) => <ClientRow cert={cert()} />}
        </Show>
      </button>

      <Show when={open()}>
        <div class="vpn-picker-backdrop" onClick={() => setOpen(false)} />
        <div class="vpn-picker-dropdown">
          <Show when={props.loading}>
            <div class="vpn-picker-loading">
              <Spinner message="Loading VPN certificates..." small />
            </div>
          </Show>

          <Show when={!props.loading && props.clients.length === 0}>
            <div class="vpn-picker-empty">No VPN certificates found</div>
          </Show>

          <For each={props.clients}>
            {(cert) => (
              <div
                class={`vpn-picker-item ${cert.serial === selectedCert()?.serial ? "vpn-picker-item-selected" : ""}`}
                onClick={() => select(cert)}
              >
                <ClientRow cert={cert} />
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  );
}
