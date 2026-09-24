import { deleteCert } from "../api/certs";
import ConfirmDialog from "./ConfirmDialog";
import { certLabel } from "../api/certActions";

export default function DeleteCertDialog(props: {
  open: boolean;
  serial: string | null;
  cn: string | null;
  onClose: () => void;
  onDone: () => void;
}) {
  return (
    <ConfirmDialog
      open={props.open}
      title="Delete Certificate"
      message={
        <>
          Delete <span class="mono">{certLabel(props)}</span>? Its 1Password item is archived
          and it leaves the certificate list. A revoked serial stays on the CRL until it expires.
        </>
      }
      confirmLabel="Delete"
      actingLabel="Deleting…"
      danger
      canConfirm={() => !!props.serial}
      onClose={props.onClose}
      onConfirm={async () => {
        const serial = props.serial;
        if (!serial) return;
        await deleteCert(serial);
        props.onDone();
      }}
    />
  );
}
