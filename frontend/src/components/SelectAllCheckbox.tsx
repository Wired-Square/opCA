import { createEffect } from "solid-js";

interface SelectAllCheckboxProps {
  all: boolean;
  some: boolean;
  onToggle: () => void;
}

/** Header checkbox for a multi-select table: checked when all visible rows are
 * selected, indeterminate when only some are. */
export default function SelectAllCheckbox(props: SelectAllCheckboxProps) {
  return (
    <input
      type="checkbox"
      class="table-checkbox"
      ref={(el) => createEffect(() => { el.indeterminate = props.some && !props.all; })}
      checked={props.all}
      onChange={props.onToggle}
      aria-label="Select all"
    />
  );
}
