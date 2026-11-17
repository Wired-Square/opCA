import { Show } from "solid-js";
import { Confirm } from "@wired-square/kit";
import { deleteCert, deleteExternalCert } from "../api/certs";
import { certLabel } from "../api/certActions";
import { createActing } from "../utils/acting";

export default function DeleteCertDialog(props: {
  open: boolean;
  serial: string | null;
  cn: string | null;
  external?: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const acting = createActing();
  return (
    <Show when={props.open}>
      <Confirm
        title="Delete Certificate"
        verb={acting.verb("Delete", "Deleting…")}
        disabled={!props.serial}
        onClose={props.onClose}
        act={acting.act(async () => {
          const serial = props.serial;
          if (!serial) return;
          await (props.external ? deleteExternalCert : deleteCert)(serial);
          props.onDone();
        })}
      >
        Delete <span class="mono">{certLabel(props)}</span>? Its 1Password item is archived
        and it leaves the certificate list.
        <Show when={!props.external}> A revoked serial stays on the CRL until it expires.</Show>
      </Confirm>
    </Show>
  );
}
