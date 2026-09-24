import { Show } from "solid-js";
import ConfirmDialog from "./ConfirmDialog";
import { deleteCsr } from "../api/csr";
import type { CsrListItem } from "../api/types";

export default function DeleteCsrDialog(props: {
  csr: CsrListItem | null;
  onClose: () => void;
  onDone: () => void;
}) {
  return (
    <ConfirmDialog
      open={!!props.csr}
      title="Delete CSR"
      message={
        <>
          Delete the CSR for <span class="mono">{props.csr?.cn ?? "—"}</span>?
          <Show when={props.csr?.status === "Pending"}>
            {" "}Its private key is archived in 1Password, so a certificate signed from it
            can no longer be imported.
          </Show>
        </>
      }
      confirmLabel="Delete"
      actingLabel="Deleting…"
      danger
      onClose={props.onClose}
      onConfirm={async () => {
        await deleteCsr(props.csr!.id!);
        props.onDone();
      }}
    />
  );
}
