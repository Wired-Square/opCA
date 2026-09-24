import { Show, For, createSignal, createMemo } from "solid-js";
import Popover, { PopoverOption } from "./Popover";
import CertStatusBadge from "./CertStatusBadge";
import Spinner from "./Spinner";
import { formatDate } from "../utils/dates";
import type { CertListItem } from "../api/types";
import "../styles/components/vpn-client-picker.css";

interface VpnClientPickerProps {
  /** Serials of the currently-selected certs. */
  selected: Set<string>;
  /** Valid vpnclient/vpnserver certificates to choose from. */
  clients: CertListItem[];
  loading: boolean;
  /** Toggle a certificate in/out of the selection. */
  onToggle: (cert: CertListItem) => void;
}

/** A single row: coloured serial badge (green = valid, orange = expiring soon)
 * prefix, then the CN, with the expiry date right-aligned. */
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
 * Multi-select dropdown for choosing VPN certificates. Unlike a native <select>
 * it renders a coloured serial badge plus the expiry date per row, so renewal
 * duplicates — two valid certs sharing a CN — can be told apart. Clicking a row
 * toggles it without closing the menu, so several certs can be picked in one
 * pass.
 */
export default function VpnClientPicker(props: VpnClientPickerProps) {
  const [open, setOpen] = createSignal(false);
  const [query, setQuery] = createSignal("");
  let triggerEl!: HTMLButtonElement;

  const isSelected = (cert: CertListItem) =>
    !!cert.serial && props.selected.has(cert.serial);

  // Typeahead over CN and serial, so a long fleet stays navigable.
  const matches = createMemo(() => {
    const q = query().trim().toLowerCase();
    if (!q) return props.clients;
    return props.clients.filter(
      (c) => (c.cn ?? "").toLowerCase().includes(q) || (c.serial ?? "").includes(q),
    );
  });

  function toggle() {
    if (!open()) setQuery("");
    setOpen(!open());
  }

  return (
    <div class="vpn-picker">
      <button
        ref={triggerEl}
        type="button"
        class="form-select vpn-picker-trigger"
        aria-haspopup="listbox"
        aria-expanded={open()}
        onClick={toggle}
      >
        <Show
          when={props.selected.size > 0}
          fallback={
            <span class="vpn-picker-placeholder">Select VPN certificate(s)</span>
          }
        >
          <span class="vpn-picker-cn">{props.selected.size} selected</span>
        </Show>
      </button>

      <Show when={open()}>
        <Popover anchor={triggerEl} matchWidth onClose={() => setOpen(false)}>
          <Show when={!props.loading && props.clients.length > 0}>
            <div class="vpn-picker-search">
              <input
                type="text"
                class="form-input"
                placeholder="Filter by name or serial…"
                value={query()}
                onInput={(e) => setQuery(e.currentTarget.value)}
                autocomplete="off"
                autocorrect="off"
                autocapitalize="off"
                spellcheck={false}
                ref={(el) => queueMicrotask(() => el.focus())}
              />
            </div>
          </Show>

          <Show when={props.loading}>
            <div class="popover-note">
              <Spinner message="Loading VPN certificates..." small />
            </div>
          </Show>

          <Show when={!props.loading && matches().length === 0}>
            <div class="popover-note">
              {props.clients.length === 0 ? "No VPN certificates found" : "No matches"}
            </div>
          </Show>

          <div class="vpn-picker-list" role="listbox" aria-multiselectable="true">
            <For each={matches()}>
              {(cert) => (
                <PopoverOption
                  class="vpn-picker-item"
                  selected={isSelected(cert)}
                  onSelect={() => props.onToggle(cert)}
                >
                  <input
                    type="checkbox"
                    class="table-checkbox table-checkbox-passive"
                    checked={isSelected(cert)}
                    tabindex={-1}
                  />
                  <ClientRow cert={cert} />
                </PopoverOption>
              )}
            </For>
          </div>
        </Popover>
      </Show>
    </div>
  );
}
