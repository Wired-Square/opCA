import { Show, For, createSignal, createMemo, onCleanup } from "solid-js";
import { Portal } from "solid-js/web";
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
 * pass. The menu is portalled with fixed positioning so it is never clipped by
 * the dialog's scroll box.
 */
export default function VpnClientPicker(props: VpnClientPickerProps) {
  const [open, setOpen] = createSignal(false);
  const [query, setQuery] = createSignal("");
  // Anchored position for the portalled dropdown (escapes the modal's clip).
  const [pos, setPos] = createSignal({ top: 0, left: 0, width: 0 });
  let triggerEl: HTMLButtonElement | undefined;

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

  function close() {
    setOpen(false);
    window.removeEventListener("resize", close);
  }
  onCleanup(close);

  function toggle() {
    if (open()) { close(); return; }
    setQuery("");
    const r = triggerEl!.getBoundingClientRect();
    setPos({ top: r.bottom + 4, left: r.left, width: r.width });
    setOpen(true);
    // The anchor is captured once; a resize invalidates it, so dismiss.
    window.addEventListener("resize", close);
  }

  return (
    <div class="vpn-picker">
      <button
        ref={triggerEl}
        type="button"
        class="form-select vpn-picker-trigger"
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
        <Portal>
          <div class="vpn-picker-backdrop" onClick={close} />
          <div
            class="vpn-picker-dropdown"
            style={{ top: `${pos().top}px`, left: `${pos().left}px`, width: `${pos().width}px` }}
          >
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

          <div class="vpn-picker-list">
            <Show when={props.loading}>
              <div class="vpn-picker-loading">
                <Spinner message="Loading VPN certificates..." small />
              </div>
            </Show>

            <Show when={!props.loading && matches().length === 0}>
              <div class="vpn-picker-empty">
                {props.clients.length === 0 ? "No VPN certificates found" : "No matches"}
              </div>
            </Show>

            <For each={matches()}>
              {(cert) => (
                <div
                  class={`vpn-picker-item ${isSelected(cert) ? "vpn-picker-item-selected" : ""}`}
                  onClick={() => props.onToggle(cert)}
                >
                  <input
                    type="checkbox"
                    class="table-checkbox table-checkbox-passive"
                    checked={isSelected(cert)}
                    tabindex={-1}
                  />
                  <ClientRow cert={cert} />
                </div>
              )}
            </For>
          </div>
          </div>
        </Portal>
      </Show>
    </div>
  );
}
