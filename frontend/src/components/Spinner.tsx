import type { JSX } from "solid-js";

interface SpinnerProps {
  /** Text to display next to the spinner. */
  message?: string;
  /** Use the smaller spinner variant. */
  small?: boolean;
  /** Extra class names on the wrapper. */
  class?: string;
}

/**
 * Inline loading spinner with an optional message.
 *
 * Usage:
 *   <Spinner />
 *   <Spinner message="Loading…" />
 *   <Spinner message="Fetching details…" small />
 */
export default function Spinner(props: SpinnerProps): JSX.Element {
  return (
    <span class={`loading-message ${props.class ?? ""}`}>
      <span class={`spinner ${props.small ? "spinner-sm" : ""}`} />
      {props.message && <span>{props.message}</span>}
    </span>
  );
}
