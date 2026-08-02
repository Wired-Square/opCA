import { revokeCert } from "../api/certs";
import ConfirmDialog from "./ConfirmDialog";
import { certLabel } from "../api/certActions";

interface RevokeCertDialogProps {
  open: boolean;
  serial: string | null;
  cn: string | null;
  onClose: () => void;
  /** Called after a successful revoke so the caller can refresh. */
  onDone: () => void;
}

/**
 * Unified revoke-confirmation dialog used from both the certificates list and
 * the certificate detail page. Owns the revoke call so both call sites are a
 * single element.
 */
export default function RevokeCertDialog(props: RevokeCertDialogProps) {
  return (
    <ConfirmDialog
      open={props.open}
      title="Revoke Certificate"
      message={
        <>
          Revoke <span class="mono">{certLabel(props)}</span>? This cannot be
          undone.
        </>
      }
      confirmLabel="Revoke"
      actingLabel="Revoking…"
      danger
      canConfirm={() => !!props.serial}
      onClose={props.onClose}
      onConfirm={async () => {
        const serial = props.serial;
        if (!serial) return;
        await revokeCert(serial);
        props.onDone();
      }}
    />
  );
}
