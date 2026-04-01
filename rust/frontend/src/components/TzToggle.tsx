import { tzMode, toggleTzMode } from "../utils/dates";
import "../styles/components/tz-toggle.css";

const modeLabel = { utc: "UTC", local: "Local", relative: "Relative" } as const;

/**
 * Small inline button to toggle between UTC, local, and relative time display.
 */
export default function TzToggle() {
  return (
    <>
      <button class="tz-toggle" onClick={toggleTzMode} title="Toggle timezone">
        {modeLabel[tzMode()]}
      </button>
    </>
  );
}
