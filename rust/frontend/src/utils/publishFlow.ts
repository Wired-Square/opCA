import { createSignal } from "solid-js";
import type { Accessor } from "solid-js";
import type { ActionResultController } from "./actionResult";

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
  const [uploading, setUploading] = createSignal(false);
  const [showPrompt, setShowPrompt] = createSignal(false);

  async function handleUpload() {
    setUploading(true);
    options.outcome.clear();
    try {
      await options.upload();
      setShowPrompt(false);
      options.outcome.report(options.success);
    } catch (e) {
      options.outcome.report("Upload failed", e);
    } finally {
      setUploading(false);
    }
  }

  return {
    uploading,
    showPrompt,
    offer: () => setShowPrompt(true),
    dismiss: () => setShowPrompt(false),
    handleUpload,
  };
}
