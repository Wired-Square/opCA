import { Show, type JSX } from "solid-js";

interface PageErrorProps {
  /** Anything throwable — coerced, so a caught value can be passed straight in.
   * Renders nothing when null/undefined, so callers need no `<Show>` wrapper. */
  message: unknown;
  /** Extra class names on the paragraph. */
  class?: string;
}

/**
 * Page-level error message, announced to assistive tech.
 *
 * Usage:
 *   <PageError message={detail.error} />
 *   <PageError message={err} class="mt-3" />
 */
export default function PageError(props: PageErrorProps): JSX.Element {
  return (
    <Show when={props.message != null}>
      <p class={props.class ? `page-error ${props.class}` : "page-error"} role="alert">
        {String(props.message)}
      </p>
    </Show>
  );
}
