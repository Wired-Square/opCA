import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@solidjs/testing-library";
import { Refusal } from "@wired-square/kit";
import EnrolBrokerDialog from "../components/EnrolBrokerDialog";
import type { BrokerOffer } from "../api/types";

const fetchBrokerOffer = vi.hoisted(() => vi.fn());
const enrolBroker = vi.hoisted(() => vi.fn());
vi.mock("../api/brokers", async (actual) => ({
  ...(await actual<object>()),
  fetchBrokerOffer,
  enrolBroker,
}));

const PAIRING = `opca-enrol://acme.home.arpa:9443#pin=${"ab".repeat(32)}&code=${"A".repeat(26)}`;

const offer = (configured_domains: string[] = []): BrokerOffer => ({
  address: "https://acme.home.arpa:9443",
  pin: "ab".repeat(32),
  offer: {
    csr_pem: "-----BEGIN CERTIFICATE REQUEST-----",
    host: "acme.home.arpa",
    configured_domains,
    versions: { api: 1, broker: "0.103.0", step_ca: "0.28.1" },
  },
});

const button = (name: string) => screen.getByRole("button", { name });
const type = (label: string | RegExp, value: string) =>
  fireEvent.input(screen.getByLabelText(label), { target: { value } });

function mount() {
  const onClose = vi.fn();
  const onDone = vi.fn();
  render(() => <EnrolBrokerDialog open onClose={onClose} onDone={onDone} />);
  return { onClose, onDone };
}

async function review(offered: BrokerOffer) {
  fetchBrokerOffer.mockResolvedValue(offered);
  type("Pairing string", `  ${PAIRING}\n`);
  button("Review").click();
  await screen.findByText(offered.pin);
}

describe("EnrolBrokerDialog", () => {
  beforeEach(() => vi.clearAllMocks());

  it("waits for a pairing string before fetching the offer", async () => {
    mount();
    expect(button("Review")).toBeDisabled();

    await review(offer());

    expect(fetchBrokerOffer).toHaveBeenCalledWith(PAIRING);
    expect(screen.getByText("acme.home.arpa")).toBeInTheDocument();
    expect(screen.getByText("https://acme.home.arpa:9443")).toBeInTheDocument();
    expect(enrolBroker).not.toHaveBeenCalled();
  });

  it("shows the broker's own domains read-only and sends none of its own", async () => {
    const enrolled = { broker: { id: 1 }, status: {} };
    enrolBroker.mockResolvedValue(enrolled);
    const { onDone, onClose } = mount();
    const offered = offer(["home.arpa"]);
    await review(offered);

    expect(screen.queryByLabelText("Permitted domains")).toBeNull();
    expect(screen.getByText("home.arpa")).toBeInTheDocument();
    button("Sign and Enrol").click();

    await vi.waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(enrolBroker).toHaveBeenCalledWith({ pairing: PAIRING, offer: offered.offer, domains: [] });
    expect(onDone).toHaveBeenCalledWith(enrolled);
  });

  it("asks for the domains when the broker has none", async () => {
    enrolBroker.mockResolvedValue({ broker: { id: 1 }, status: {} });
    mount();
    await review(offer());
    expect(button("Sign and Enrol")).toBeDisabled();

    type("Permitted domains", "home.arpa\nlab.example");
    button("Sign and Enrol").click();

    await vi.waitFor(() => expect(enrolBroker).toHaveBeenCalled());
    expect(enrolBroker.mock.calls[0][0].domains).toEqual(["home.arpa", "lab.example"]);
  });

  it("keeps the dialog open with the refusal when the hand-over fails", async () => {
    enrolBroker.mockRejectedValue(new Refusal("Subordinate 3 is signed, but the broker did not take it"));
    const { onClose } = mount();
    await review(offer(["home.arpa"]));

    button("Sign and Enrol").click();

    expect(await screen.findByRole("alert")).toHaveTextContent("did not take it");
    expect(onClose).not.toHaveBeenCalled();
    expect(button("Sign and Enrol")).not.toBeDisabled();
  });
});
