import { createSignal, onCleanup } from "solid-js";
import type { Accessor } from "solid-js";

/**
 * Reactive "copied" signal that auto-resets after a timeout,
 * with proper cleanup on component unmount.
 */
export function createCopiedSignal(ms = 2000): [Accessor<boolean>, () => void] {
  const [copied, setCopied] = createSignal(false);
  let timer: number | undefined;

  const trigger = () => {
    setCopied(true);
    clearTimeout(timer);
    timer = window.setTimeout(() => setCopied(false), ms);
  };

  onCleanup(() => clearTimeout(timer));

  return [copied, trigger];
}
