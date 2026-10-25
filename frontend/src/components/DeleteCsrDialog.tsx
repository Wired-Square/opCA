import { Show } from "solid-js";
import { Confirm } from "@wired-square/kit";
import { deleteCsr } from "../api/csr";
import type { CsrListItem } from "../api/types";
import { createActing } from "../utils/acting";

export default function DeleteCsrDialog(props: {
  csr: CsrListItem | null;
  onClose: () => void;
  onDone: () => void;
}) {
  const acting = createActing();
  return (
    <Show when={props.csr}>
      {(csr) => (
        <Confirm
          title="Delete CSR"
          verb={acting.verb("Delete", "Deleting…")}
          onClose={props.onClose}
          act={acting.act(async () => {
            await deleteCsr(csr().id!);
            props.onDone();
          })}
        >
          Delete the CSR for <span class="mono">{csr().cn ?? "—"}</span>?
          <Show when={csr().status === "Pending"}>
            {" "}Its private key is archived in 1Password, so a certificate signed from it
            can no longer be imported.
          </Show>
        </Confirm>
      )}
    </Show>
  );
}
