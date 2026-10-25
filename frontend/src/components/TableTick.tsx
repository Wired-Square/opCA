import { Tick, type TickProps } from "@wired-square/kit";

type TableTickProps = Omit<TickProps, "label" | "hint"> & { label: string };

/** A table's selection tickbox, named for screen readers only. */
export default function TableTick(props: TableTickProps) {
  return <Tick {...props} label={<span class="app-visually-hidden">{props.label}</span>} />;
}
