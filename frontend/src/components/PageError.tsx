import { Show, type JSX } from "solid-js";

interface PageErrorProps {
  /** Anything throwable — coerced, so a caught value can be passed straight in.
   * Renders nothing when null, undefined or empty, so callers need no `<Show>` wrapper. */
  message: unknown;
  /** `"form"` sits the message under a form rather than above page content. */
  placement?: "page" | "form";
  /** Extra class names on the paragraph. */
  class?: string;
}

/**
 * Page-level error message, announced to assistive tech.
 *
 * Usage:
 *   <PageError message={detail.error} />
 *   <PageError message={error()} placement="form" />
 */
export default function PageError(props: PageErrorProps): JSX.Element {
  const classes = () =>
    ["page-error", props.placement === "form" && "page-error--form", props.class]
      .filter(Boolean)
      .join(" ");
  return (
    <Show when={props.message != null && props.message !== ""}>
      <p class={classes()} role="alert">
        {String(props.message)}
      </p>
    </Show>
  );
}
