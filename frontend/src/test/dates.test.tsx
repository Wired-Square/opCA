import { describe, it, expect, vi, afterEach } from "vitest";
import { cleanup, render, screen, fireEvent } from "@solidjs/testing-library";
import { DateModeToggle, DateModes } from "@wired-square/kit";
import StoredDate from "../components/StoredDate";
import { asn1Date, formatRelativeTime, useDateText } from "../utils/dates";

vi.stubEnv("TZ", "Australia/Sydney");

const NOW = Date.UTC(2026, 9, 25, 21, 8, 29);
const ago = (seconds: number) => new Date(NOW - seconds * 1000);
const ahead = (seconds: number) => new Date(NOW + seconds * 1000);

describe("asn1Date", () => {
  it("reads GeneralizedTime as UTC", () => {
    expect(asn1Date("20261025210829Z")?.getTime()).toBe(NOW);
  });

  it("falls back to the platform's parsing, and gives null for nonsense", () => {
    expect(asn1Date("Oct 25 21:08:29 2026 GMT")?.getTime()).toBe(NOW);
    expect(asn1Date("not a date")).toBeNull();
  });
});

describe("formatRelativeTime", () => {
  it("counts down to a future date in its two largest units", () => {
    expect(formatRelativeTime(new Date(Date.UTC(2029, 0, 26)), NOW)).toBe("2y 3mo");
    expect(formatRelativeTime(ahead(45 * 86_400 + 12 * 3_600), NOW)).toBe("45d 12h");
    expect(formatRelativeTime(ahead(4 * 3_600 + 12 * 60 + 30), NOW)).toBe("4h 12m 30s");
    expect(formatRelativeTime(ahead(12 * 60 + 30), NOW)).toBe("12m 30s");
    expect(formatRelativeTime(ahead(45), NOW)).toBe("45s");
  });

  it("says how long ago a past date was", () => {
    expect(formatRelativeTime(ago(30), NOW)).toBe("just now");
    expect(formatRelativeTime(ago(60), NOW)).toBe("1 minute ago");
    expect(formatRelativeTime(ago(3 * 3_600), NOW)).toBe("3 hours ago");
    expect(formatRelativeTime(ago(5 * 86_400), NOW)).toBe("5 days ago");
    expect(formatRelativeTime(new Date(Date.UTC(2025, 7, 20)), NOW)).toBe("1 year, 2 months ago");
  });
});

describe("dates under DateModes", () => {
  afterEach(() => vi.useRealTimers());

  function FilterText(props: { value: string | null }) {
    const text = useDateText();
    return <output>{text(props.value)}</output>;
  }

  function mount(value: string | null) {
    render(() => (
      <DateModes initial="utc" locale="en-AU" relative={formatRelativeTime}>
        <DateModeToggle />
        <p data-testid="when">
          <StoredDate value={value} />
        </p>
        <FilterText value={value} />
      </DateModes>
    ));
    return {
      shown: () => screen.getByTestId("when").textContent,
      text: () => screen.getByRole("status").textContent,
    };
  }

  it("shows opca's UTC, local and ticking relative strings, in step with the filter text", () => {
    vi.useFakeTimers({ now: NOW - 45_000 });
    const { shown, text } = mount("20261025210829Z");
    expect(shown()).toBe("25 Oct 2026, 21:08:29 UTC");
    expect(text()).toBe(shown());

    fireEvent.click(screen.getByRole("button", { name: "UTC" }));
    expect(shown()).toBe("26 Oct 2026, 08:08:29 AEDT");
    expect(text()).toBe(shown());

    fireEvent.click(screen.getByRole("button", { name: "Local" }));
    expect(screen.getByRole("button", { name: "Relative" })).toBeInTheDocument();
    expect(shown()).toBe("45s");
    vi.advanceTimersByTime(1_000);
    expect(shown()).toBe("44s");
    expect(text()).toBe(shown());
  });

  it("shows a dash for no date and the stored text for one it cannot read", () => {
    expect(mount(null).shown()).toBe("—");
    cleanup();
    expect(mount("someday").shown()).toBe("someday");
  });
});
