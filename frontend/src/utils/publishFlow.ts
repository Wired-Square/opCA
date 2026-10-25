import { createSignal } from "solid-js";
import type { Accessor } from "solid-js";
import { createAction, type Action } from "@wired-square/kit";
import { headed } from "./acting";

/** The upload's own `Action`: `pending()` for the buttons, its outcome for `ActionOutcome`. */
export interface PublishFlow extends Action {
  showPrompt: Accessor<boolean>;
  /** Offer the upload, after the artefact it publishes has changed. */
  offer: () => void;
  dismiss: () => void;
  /** Uploads and reports the outcome. Never throws. */
  handleUpload: () => Promise<void>;
}

interface PublishFlowOptions {
  upload: () => Promise<void>;
  /** Success sentence, e.g. "CRL uploaded to public store". */
  success: string;
}

/**
 * Publishing a freshly-changed artefact to a store.
 *
 * The backend does not upload as part of generating or re-signing, so the copy
 * in the store goes stale until someone presses Upload. Pages call `offer()`
 * after the change to raise the prompt, and share `pending` with their own
 * header button.
 *
 * Holds state only — render the prompt with `components/UploadPrompt`.
 */
export function createPublishFlow(options: PublishFlowOptions): PublishFlow {
  const [showPrompt, setShowPrompt] = createSignal(false);
  const action = createAction();

  return {
    ...action,
    showPrompt,
    offer: () => setShowPrompt(true),
    dismiss: () => setShowPrompt(false),
    // The prompt stays up on failure so the user can retry from it.
    handleUpload: () =>
      action.run(headed("Upload failed", options.upload), () => {
        setShowPrompt(false);
        action.succeed(options.success);
      }),
  };
}
