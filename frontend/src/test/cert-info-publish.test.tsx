import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import CertInfo from "../pages/CertInfo";
import { renewAndGo } from "../api/certActions";
import type { CertDetail } from "../api/types";

const getCertInfo = vi.hoisted(() => vi.fn());
const backfillCert = vi.hoisted(() => vi.fn());
const publishCert = vi.hoisted(() => vi.fn());
const renewCert = vi.hoisted(() => vi.fn());
const navigate = vi.hoisted(() => vi.fn());
const searchParams = vi.hoisted(() => ({}) as Record<string, string>);
vi.mock("../api/certs", async (actual) => ({
  ...(await actual<object>()),
  getCertInfo,
  backfillCert,
  publishCert,
  renewCert,
  forgetPreloadedKey: vi.fn(() => Promise.resolve()),
}));
vi.mock("@solidjs/router", () => ({
  useParams: () => ({ serial: "7" }),
  useNavigate: () => navigate,
  useSearchParams: () => [searchParams],
}));

const cert = (overrides: Partial<CertDetail> = {}): CertDetail =>
  ({
    serial: "7",
    cn: "www.example.com",
    title: "CRT_7_www.example.com",
    status: "Valid",
    cert_type: "webserver",
    expiry_date: "20271027000000Z",
    cert_pem: "-----BEGIN CERTIFICATE-----",
    published_at: null,
    ...overrides,
  }) as CertDetail;

const openActions = () => fireEvent.click(screen.getByRole("button", { name: "Certificate actions" }));

describe("certificate detail publishing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    for (const key of Object.keys(searchParams)) delete searchParams[key];
    backfillCert.mockImplementation(() => new Promise(() => {}));
  });

  it("shows the Published badge and when, only once published", async () => {
    getCertInfo.mockResolvedValue(cert({ published_at: "20261027093000Z" }));
    render(() => <CertInfo />);

    expect(await screen.findByText("published")).toHaveClass("status-badge");
    expect(screen.getByText("Published")).toHaveClass("detail-label");
  });

  it("publishes from the actions menu and then shows the badge", async () => {
    getCertInfo
      .mockResolvedValueOnce(cert())
      .mockResolvedValueOnce(cert({ published_at: "20261027093000Z" }));
    publishCert.mockResolvedValue("s3://bucket/certs/www.example.com.pem");
    render(() => <CertInfo />);
    await screen.findByText("CRT_7_www.example.com");
    expect(screen.queryByText("published")).not.toBeInTheDocument();

    openActions();
    fireEvent.click(screen.getByRole("menuitem", { name: "Publish" }));

    expect(
      await screen.findByText("Published www.example.com to s3://bucket/certs/www.example.com.pem"),
    ).toBeInTheDocument();
    expect(publishCert).toHaveBeenCalledWith("7");
    expect(screen.getByText("published")).toBeInTheDocument();
  });

  it("offers no Publish on a revoked certificate", async () => {
    getCertInfo.mockResolvedValue(cert({ status: "Revoked" }));
    render(() => <CertInfo />);
    await screen.findByText("CRT_7_www.example.com");

    openActions();
    expect(screen.queryByRole("menuitem", { name: "Publish" })).not.toBeInTheDocument();
  });

  it("says when a renewal's republish failed, and that Publish retries it", async () => {
    Object.assign(searchParams, { freshFrom: "6", op: "renew", publishError: "rsync exited 23" });
    getCertInfo.mockResolvedValue(cert());
    render(() => <CertInfo />);

    expect(
      await screen.findByText(
        "The renewal was not published: rsync exited 23. Publish it from the actions menu to try again.",
      ),
    ).toBeInTheDocument();
  });
});

describe("renewAndGo", () => {
  it("carries the republish outcome to the new certificate", async () => {
    renewCert.mockResolvedValueOnce({ serial: "8", pem: "", published_to: null, publish_error: "no store" });
    await renewAndGo(navigate, "7");
    expect(navigate).toHaveBeenLastCalledWith("/certs/8?freshFrom=7&op=renew&publishError=no+store");

    renewCert.mockResolvedValueOnce({ serial: "9", pem: "", published_to: "s3://b/certs/a.pem", publish_error: null });
    await renewAndGo(navigate, "8");
    expect(navigate).toHaveBeenLastCalledWith("/certs/9?freshFrom=8&op=renew&publishedTo=s3%3A%2F%2Fb%2Fcerts%2Fa.pem");
  });
});
