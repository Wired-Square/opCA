import { ErrorBoundary, type ParentProps } from "solid-js";
import PageError from "./PageError";

/**
 * Catches anything a page throws during render — most often a resource getter
 * rethrowing a failed load, which would otherwise blank the window.
 *
 * Navigating away recovers on its own (the router rebuilds the outlet), so the
 * fallback only needs to offer retrying in place. See
 * `test/route-error-boundary.test.tsx`, which pins both behaviours.
 */
export default function RouteErrorBoundary(props: ParentProps) {
  return (
    <ErrorBoundary
      fallback={(err, reset) => (
        <div class="p-4 page-crash">
          <h2 class="mb-3">Something went wrong</h2>
          <PageError message={err} />
          <button class="btn-primary" onClick={reset}>Try again</button>
        </div>
      )}
    >
      {props.children}
    </ErrorBoundary>
  );
}
