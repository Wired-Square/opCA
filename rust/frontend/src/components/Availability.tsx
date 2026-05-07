import { Match, Show, Switch } from "solid-js";

interface AvailabilityProps {
  label: string;
  /** `true` = stored, `false` = absent, `null` = not yet known (pre-backfill). */
  available: boolean | null;
  /** Optional copy handler. When provided, the indicator becomes a button
   * that triggers `onCopy` on click — only enabled while `available === true`
   * and `busy` is falsy. */
  onCopy?: () => void | Promise<void>;
  busy?: boolean;
  copied?: boolean;
  /** When set, the indicator never lets the user copy: it renders as a
   * disabled button with this string as the tooltip. Used for material we
   * deliberately refuse to surface (e.g. CA private keys). Takes precedence
   * over `onCopy`. */
  blocked?: string;
}

/**
 * Tag indicating whether an artefact (private key, chain, etc.) is stored
 * alongside a certificate. When `onCopy` is provided, the indicator doubles
 * as the copy action so the user can grab the artefact without scrolling
 * to find a separate button. The class is computed via a function so Solid
 * re-evaluates it whenever `props.available` changes (e.g. mid-backfill).
 */
export default function Availability(props: AvailabilityProps) {
  const cls = () => {
    const parts = ["stored-tag"];
    if (props.available === true) parts.push("stored-yes");
    else if (props.available === false) parts.push("stored-no");
    else parts.push("stored-unknown");
    if (props.blocked) {
      parts.push("stored-blocked");
    } else if (props.onCopy && props.available === true && !props.busy) {
      parts.push("stored-clickable");
    }
    return parts.join(" ");
  };

  if (props.blocked) {
    return (
      <button type="button" class={cls()} disabled title={props.blocked}>
        <span>{props.label}</span>
        <LockIcon />
      </button>
    );
  }

  if (!props.onCopy) {
    return <span class={cls()}>{props.label}</span>;
  }

  const disabled = () => props.available !== true || !!props.busy;
  const title = () => props.available === true
    ? `Copy ${props.label} to clipboard`
    : `${props.label} not stored alongside this certificate`;

  return (
    <button
      type="button"
      class={cls()}
      onClick={() => { void props.onCopy?.(); }}
      disabled={disabled()}
      title={title()}
    >
      <Switch fallback={
        <>
          <span>{props.label}</span>
          <Show when={props.available === true}>
            <CopyIcon />
          </Show>
        </>
      }>
        <Match when={props.busy}>
          <span>Copying…</span>
        </Match>
        <Match when={props.copied}>
          <span>Copied</span>
        </Match>
      </Switch>
    </button>
  );
}

function LockIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      class="stored-copy-icon"
    >
      <rect x="3" y="7" width="10" height="7" rx="1" />
      <path d="M5 7V5a3 3 0 0 1 6 0v2" />
    </svg>
  );
}

function CopyIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      class="stored-copy-icon"
    >
      <rect x="5" y="5" width="9" height="10" rx="1" />
      <path d="M3 11V3a1 1 0 0 1 1-1h7" />
    </svg>
  );
}
