import { describe, it, expect } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import { For, createSignal } from "solid-js";
import { createSelection } from "@wired-square/kit";
import TableTick from "../components/TableTick";

function mount() {
  const [rows] = createSignal(["a", "b"]);
  render(() => {
    const sel = createSelection(rows, (r) => r, rows);
    return (
      <table>
        <thead>
          <tr>
            <th class="checkbox-col">
              <TableTick
                label="Select all"
                checked={sel.allSelected()}
                mixed={sel.someSelected() && !sel.allSelected()}
                onChange={sel.toggleAll}
              />
            </th>
          </tr>
        </thead>
        <tbody>
          <For each={rows()}>
            {(row) => (
              <tr>
                <td class="checkbox-col">
                  <TableTick label={`Select ${row}`} checked={sel.isSelected(row)} onChange={() => sel.toggle(row)} />
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    );
  });
  return (name: string) => screen.getByRole("checkbox", { name }) as HTMLInputElement;
}

describe("TableTick", () => {
  it("shows a partial selection as mixed on the select-all box", () => {
    const box = mount();
    fireEvent.click(box("Select a"));
    expect(box("Select all").indeterminate).toBe(true);
    expect(box("Select all")).not.toBeChecked();
    fireEvent.click(box("Select b"));
    expect(box("Select all").indeterminate).toBe(false);
    expect(box("Select all")).toBeChecked();
  });

  it("selects every row from select-all, then clears them", () => {
    const box = mount();
    fireEvent.click(box("Select all"));
    expect(box("Select a")).toBeChecked();
    expect(box("Select b")).toBeChecked();
    fireEvent.click(box("Select all"));
    expect(box("Select a")).not.toBeChecked();
    expect(box("Select b")).not.toBeChecked();
  });
});
