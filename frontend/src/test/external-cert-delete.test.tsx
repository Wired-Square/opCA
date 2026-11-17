import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import Certs from "../pages/Certs";
import ExternalCertInfo from "../pages/ExternalCertInfo";
import type { ExternalCertDetail } from "../api/types";

const listCerts = vi.hoisted(() => vi.fn());
const listExternalCerts = vi.hoisted(() => vi.fn());
const getExternalCertInfo = vi.hoisted(() => vi.fn());
const backfillExternalCert = vi.hoisted(() => vi.fn());
const deleteExternalCert = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
vi.mock("../api/certs", async (actual) => ({
  ...(await actual<object>()),
  listCerts,
  listExternalCerts,
  getExternalCertInfo,
  backfillExternalCert,
  deleteExternalCert,
  forgetPreloadedKey: vi.fn(() => Promise.resolve()),
}));
vi.mock("@solidjs/router", () => ({
  useParams: () => ({ serial: "ABC123" }),
  useNavigate: () => navigate,
  useSearchParams: () => [{ tab: "external", filter: "all" }],
}));

const EXTERNAL = {
  serial: "ABC123",
  cn: "ext.example.com",
  title: "ext.example.com",
  status: "Valid",
  issuer: "Public CA",
  expiry_date: "20351231235959Z",
} as ExternalCertDetail;

async function confirmDelete() {
  fireEvent.click(await screen.findByRole("button", { name: "Delete" }));
}

describe("deleting an external certificate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    deleteExternalCert.mockResolvedValue(undefined);
  });

  it("is offered on a valid row of the External tab, which then refreshes", async () => {
    listCerts.mockResolvedValue([]);
    listExternalCerts
      .mockResolvedValueOnce([EXTERNAL])
      .mockResolvedValueOnce([]);
    render(() => <Certs />);
    await screen.findByText("ext.example.com");

    fireEvent.click(screen.getByRole("button", { name: "Actions" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Delete" }));
    await confirmDelete();

    expect(await screen.findByText("Deleted ext.example.com")).toBeInTheDocument();
    expect(deleteExternalCert).toHaveBeenCalledWith("ABC123");
    expect(listExternalCerts).toHaveBeenCalledTimes(2);
  });

  it("is offered on the detail page, which then returns to the External tab", async () => {
    getExternalCertInfo.mockResolvedValue(EXTERNAL);
    backfillExternalCert.mockImplementation(() => new Promise(() => {}));
    render(() => <ExternalCertInfo />);
    await screen.findByText("Public CA");

    fireEvent.click(screen.getByRole("button", { name: "Certificate actions" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Delete" }));
    await confirmDelete();

    await vi.waitFor(() => expect(navigate).toHaveBeenCalledWith("/certs?tab=external"));
    expect(deleteExternalCert).toHaveBeenCalledWith("ABC123");
  });
});
