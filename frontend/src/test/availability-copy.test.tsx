import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@solidjs/testing-library";
import CRL from "../pages/CRL";
import type { CrlInfo } from "../api/types";

const writeText = vi.hoisted(() => vi.fn(async (_text: string) => {}));
const recordCrlCopy = vi.hoisted(() => vi.fn(async () => {}));
const crlInfo = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({ writeText }));
vi.mock("../api/crl", async (actual) => ({
  ...(await actual<object>()),
  getCrlInfo: crlInfo,
  backfillCrl: crlInfo,
  recordCrlCopy,
}));
vi.mock("@solidjs/router", () => ({ useNavigate: () => vi.fn() }));

const info: CrlInfo = {
  issuer: "CN=Test CA",
  last_update: "20260925000000Z",
  next_update: "20261005000000Z",
  crl_number: 6,
  revoked_count: 0,
  crl_pem: "-----BEGIN X509 CRL-----",
  has_public_store: false,
  has_crl: true,
  crl_batch_enabled: false,
  crl_batch: null,
};

const crlDocument = () => screen.findByRole("button", { name: "CRL Document" });

describe("Availability copy", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    crlInfo.mockResolvedValue(info);
  });

  it("says Copied and records the copy only once the write has landed", async () => {
    let land!: () => void;
    writeText.mockImplementationOnce(() => new Promise<void>((resolve) => (land = resolve)));
    render(() => <CRL />);
    fireEvent.click(await crlDocument());
    expect(writeText).toHaveBeenCalledWith(info.crl_pem);
    expect(screen.queryByText("Copied")).toBeNull();
    expect(recordCrlCopy).not.toHaveBeenCalled();
    land();
    expect(await screen.findByText("Copied")).toBeInTheDocument();
    expect(recordCrlCopy).toHaveBeenCalledOnce();
  });

  it("neither says Copied nor records a copy the clipboard refused", async () => {
    writeText.mockRejectedValueOnce(new Error("denied"));
    render(() => <CRL />);
    fireEvent.click(await crlDocument());
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    await Promise.resolve();
    await Promise.resolve();
    expect(screen.queryByText("Copied")).toBeNull();
    expect(recordCrlCopy).not.toHaveBeenCalled();
  });
});
