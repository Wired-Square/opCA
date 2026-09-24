import { ignoreCert } from "../api/certs";
import ConfirmDialog from "./ConfirmDialog";
import { certLabel } from "../api/certActions";

interface IgnoreCertDialogProps {
  open: boolean;
  serial: string | null;
  cn: string | null;
  onClose: () => void;
  /** Called after a successful ignore so the caller can refresh. */
  onDone: () => void;
}

/**
 * Unified "ignore certificate" dialog used from both the certificates list and
 * the certificate detail page. A reason is required — Confirm stays disabled
 * until the field is non-empty.
 */
export default function IgnoreCertDialog(props: IgnoreCertDialogProps) {
  return (
    <ConfirmDialog
      open={props.open}
      title="Ignore Certificate"
      message={
        <>
          Stop counting <span class="mono">{certLabel(props)}</span> toward
          expiry alerts. Provide a reason for the audit trail.
        </>
      }
      confirmLabel="Confirm Ignore"
      actingLabel="Ignoring…"
      requireReason
      reasonPlaceholder="Why is this being ignored?"
      canConfirm={() => !!props.serial}
      onClose={props.onClose}
      onConfirm={async (reason) => {
        const serial = props.serial;
        if (!serial) return;
        await ignoreCert(serial, reason);
        props.onDone();
      }}
    />
  );
}
