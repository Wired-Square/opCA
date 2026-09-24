import { Show, type JSX } from "solid-js";
import TzToggle from "./TzToggle";
import { formatDate } from "../utils/dates";

export type StatusTone = "success" | "warning" | "error" | "muted";
export type WarningLevel =
  | "critical"
  | "prominent"
  | "cert_lifetime"
  | "expired"
  | "none";

export interface StatusBubbleWarning {
  level: WarningLevel;
  message: string;
}

export interface StatusBubbleProps {
  label: string;
  status: string;
  tone?: StatusTone;
  /** Short prefix for the detail line, e.g. "expires" or "next update". */
  detailPrefix?: string;
  /** Raw date string, passed through `formatDate`. Hides the detail row when null. */
  detailDate?: string | null;
  warning?: StatusBubbleWarning | null;
  onClick?: () => void;
  children?: JSX.Element;
}

const toneClass: Record<StatusTone, string> = {
  success: "text-success",
  warning: "text-warning",
  error: "text-error",
  muted: "text-muted",
};

function warningClass(level: WarningLevel): string {
  switch (level) {
    case "critical":
    case "expired":
      return "stat-card-warning stat-card-warning--critical";
    case "prominent":
    case "cert_lifetime":
      return "stat-card-warning stat-card-warning--warning";
    default:
      return "stat-card-warning";
  }
}

/**
 * Status card with a label, coloured status value, optional expiry date with a
 * timezone toggle in the top-right, and an optional graduated warning line.
 */
export default function StatusBubble(props: StatusBubbleProps) {
  const clickable = () => props.onClick !== undefined;

  const handleKeyDown = (e: KeyboardEvent) => {
    if (!props.onClick) return;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      props.onClick();
    }
  };

  return (
    <div
      class="stat-card"
      classList={{ "stat-card-clickable": clickable() }}
      onClick={props.onClick}
      role={clickable() ? "button" : undefined}
      tabIndex={clickable() ? 0 : undefined}
      onKeyDown={clickable() ? handleKeyDown : undefined}
    >
      <div class="stat-card-header">
        <span class="stat-label">{props.label}</span>
        <Show when={props.detailDate}>
          <TzToggle />
        </Show>
      </div>
      <span class="stat-value">
        <span class={toneClass[props.tone ?? "muted"]}>{props.status}</span>
      </span>
      <Show when={props.detailDate}>
        <span class="stat-card-detail">
          {props.detailPrefix ? `${props.detailPrefix} ` : ""}
          <span class="mono">{formatDate(props.detailDate ?? null)}</span>
        </span>
      </Show>
      <Show when={props.warning}>
        {(w) => <span class={warningClass(w().level)}>{w().message}</span>}
      </Show>
      {props.children}
    </div>
  );
}
