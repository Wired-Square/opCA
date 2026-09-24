import { Show } from "solid-js";
import type { PublishFlow } from "../utils/publishFlow";

interface UploadPromptProps {
  flow: PublishFlow;
  message: string;
}

/** Offers to publish a freshly-changed artefact to its store. Raised by
 * `createPublishFlow`'s `offer()` and dismissable. */
export default function UploadPrompt(props: UploadPromptProps) {
  return (
    <Show when={props.flow.showPrompt()}>
      <div class="upload-prompt">
        <span>{props.message}</span>
        <div class="upload-actions">
          <button
            class="btn-primary btn-sm"
            onClick={props.flow.handleUpload}
            disabled={props.flow.uploading()}
          >
            {props.flow.uploading() ? "Uploading…" : "Upload"}
          </button>
          <button class="btn-ghost btn-sm" onClick={props.flow.dismiss}>
            Dismiss
          </button>
        </div>
      </div>
    </Show>
  );
}
