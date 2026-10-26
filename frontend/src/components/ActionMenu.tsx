import { For } from "solid-js";
import { Menu, MenuItem } from "@wired-square/kit";

export interface MenuAction {
  label: string;
  onSelect: () => void;
  disabled?: boolean;
  danger?: boolean;
}

/** A row's or a page's actions behind the kit's ⋮ menu. */
export default function ActionMenu(props: { items: MenuAction[]; "aria-label"?: string }) {
  return (
    <Menu aria-label={props["aria-label"] ?? "Actions"}>
      <For each={props.items}>
        {(item) => (
          <MenuItem danger={item.danger} disabled={item.disabled} onSelect={item.onSelect}>
            {item.label}
          </MenuItem>
        )}
      </For>
    </Menu>
  );
}
