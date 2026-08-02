import { createSignal } from "solid-js";
import type { Accessor } from "solid-js";
import type { ActionResultController } from "./actionResult";
import { createAction } from "./action";

export interface PublishFlow {
  /** True while the upload is in flight — for the button label. */
  uploading: Accessor<boolean>;
  showPrompt: Accessor<boolean>;
  /** Offer the upload, after the artefact it publishes has changed. */
  offer: () => void;
  dismiss: () => void;
  /** Uploads and reports through the page's banner. Never throws. */
  handleUpload: () => Promise<void>;
}

interface PublishFlowOptions {
  upload: () => Promise<void>;
  /** Banner headline on success, e.g. "CRL uploaded to public store". */
  success: string;
  /** The page's controller — pages report other actions through it too. */
  outcome: ActionResultController;
}

/**
 * Publishing a freshly-changed artefact to a store.
 *
 * The backend does not upload as part of generating or re-signing, so the copy
 * in the store goes stale until someone presses Upload. Pages call `offer()`
 * after the change to raise the prompt, and share `uploading` with their own
 * header button.
 *
 * Holds state only — render the prompt with `components/UploadPrompt`.
 */
export function createPublishFlow(options: PublishFlowOptions): PublishFlow {
  const [showPrompt, setShowPrompt] = createSignal(false);
  const action = createAction(options.outcome);

  return {
    uploading: action.busy,
    showPrompt,
    offer: () => setShowPrompt(true),
    dismiss: () => setShowPrompt(false),
    // The prompt stays up on failure so the user can retry from it.
    handleUpload: () =>
      action.run({ success: options.success, failure: "Upload failed" }, async () => {
        await options.upload();
        setShowPrompt(false);
      }),
  };
}
