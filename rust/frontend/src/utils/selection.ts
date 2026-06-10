import { createSignal, createMemo, createEffect, type Accessor } from "solid-js";

export interface Selection<T> {
  /** The set of selected keys. */
  selected: Accessor<Set<string>>;
  /** The currently-visible items that are selected. */
  selectedItems: Accessor<T[]>;
  isSelected: (key: string) => boolean;
  toggle: (key: string) => void;
  clear: () => void;
  /** Select all visible items, or clear if all are already selected. */
  toggleAll: () => void;
  allSelected: Accessor<boolean>;
  someSelected: Accessor<boolean>;
}

/**
 * Multi-select over a reactive list of `visible` items. `keyOf` returns a stable
 * id per item (or null to make a row unselectable). The selection auto-clears
 * whenever `resetOn` changes — pass the backing resource so a refetch drops
 * stale ids rather than leaving them selected.
 */
export function createSelection<T>(
  visible: Accessor<T[]>,
  keyOf: (item: T) => string | null,
  resetOn: Accessor<unknown>,
): Selection<T> {
  const [selected, setSelected] = createSignal<Set<string>>(new Set());
  const clear = () => setSelected(new Set<string>());

  createEffect(() => { resetOn(); clear(); });

  const keys = () => visible().map(keyOf).filter((k): k is string => !!k);
  const selectedItems = createMemo(() =>
    visible().filter((it) => {
      const k = keyOf(it);
      return !!k && selected().has(k);
    }),
  );
  const allSelected = () => {
    const k = keys();
    return k.length > 0 && k.every((x) => selected().has(x));
  };

  return {
    selected,
    selectedItems,
    allSelected,
    isSelected: (k) => selected().has(k),
    someSelected: () => keys().some((k) => selected().has(k)),
    clear,
    toggle: (k) =>
      setSelected((s) => {
        const n = new Set(s);
        n.has(k) ? n.delete(k) : n.add(k);
        return n;
      }),
    toggleAll: () => (allSelected() ? clear() : setSelected(new Set(keys()))),
  };
}
