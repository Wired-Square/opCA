import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@solidjs/testing-library";
import DeleteCsrDialog from "../components/DeleteCsrDialog";
import type { CsrListItem } from "../api/types";

const deleteCsr = vi.hoisted(() => vi.fn());
vi.mock("../api/csr", async (actual) => ({ ...(await actual<object>()), deleteCsr }));

const csr = (status: string): CsrListItem => ({
  id: 7, cn: "old.example.com", title: "CSR_old.example.com", csr_type: "webserver",
  email: null, subject: null, status, created_date: null, stale: true,
});

describe("DeleteCsrDialog", () => {
  it("warns that a pending CSR's key goes with it", () => {
    render(() => <DeleteCsrDialog csr={csr("Pending")} onClose={() => {}} onDone={() => {}} />);
    expect(screen.getByText("old.example.com")).toBeInTheDocument();
    expect(screen.getByText(/private key is archived/)).toBeInTheDocument();
  });

  it("gives no key warning for a completed CSR", () => {
    render(() => <DeleteCsrDialog csr={csr("Complete")} onClose={() => {}} onDone={() => {}} />);
    expect(screen.queryByText(/private key/)).not.toBeInTheDocument();
  });

  it("deletes by id and reports back", async () => {
    deleteCsr.mockResolvedValue(undefined);
    const onDone = vi.fn();
    const onClose = vi.fn();
    render(() => <DeleteCsrDialog csr={csr("Pending")} onClose={onClose} onDone={onDone} />);

    screen.getByRole("button", { name: /^Delete/ }).click();

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(deleteCsr).toHaveBeenCalledWith(7);
    expect(onDone).toHaveBeenCalled();
  });
});
