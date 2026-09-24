/** Shared "copy to clipboard" glyph. Used by click-to-copy affordances
 * (Availability tags, CopyableValue, etc.). */
export default function CopyIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      stroke-width="1.5"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      class="stored-copy-icon"
    >
      <rect x="5" y="5" width="9" height="10" rx="1" />
      <path d="M3 11V3a1 1 0 0 1 1-1h7" />
    </svg>
  );
}
