import { Show } from "solid-js";
import { Confirm } from "@wired-square/kit";
import { ignoreCert } from "../api/certs";
import { certLabel } from "../api/certActions";
import { createActing } from "../utils/acting";

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
  const acting = createActing();
  return (
    <Show when={props.open}>
      <Confirm
        title="Ignore Certificate"
        verb={acting.verb("Confirm Ignore", "Ignoring…")}
        tone="primary"
        reason={{ label: "Reason", placeholder: "Why is this being ignored?" }}
        disabled={!props.serial}
        onClose={props.onClose}
        act={acting.act(async (reason: string) => {
          const serial = props.serial;
          if (!serial) return;
          await ignoreCert(serial, reason);
          props.onDone();
        })}
      >
        Stop counting <span class="mono">{certLabel(props)}</span> toward
        expiry alerts. Provide a reason for the audit trail.
      </Confirm>
    </Show>
  );
}
