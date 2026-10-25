import { Show } from "solid-js";
import { When } from "@wired-square/kit";
import { asn1Date } from "../utils/dates";

/** A stored date in the current `DateModes` mode: "—" when missing, as stored when unreadable. */
export default function StoredDate(props: { value: string | null | undefined }) {
  const at = () => (props.value ? asn1Date(props.value) : null);
  return (
    <Show when={at()} fallback={props.value || "—"}>
      {(date) => <When at={date()} />}
    </Show>
  );
}
