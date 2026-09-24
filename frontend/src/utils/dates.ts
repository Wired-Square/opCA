/**
 * Date display utilities for opCA.
 *
 * Dates are stored in ASN1 GeneralizedTime format: "20270415051336Z"
 * We parse them and display in a human-friendly format, with the ability
 * to toggle between UTC, local time, and relative time.
 */

import { createSignal, createEffect, createRoot, onCleanup } from "solid-js";

export type TimeZoneMode = "utc" | "local" | "relative";

const [tzMode, setTzMode] = createSignal<TimeZoneMode>("utc");

export { tzMode };

export function toggleTzMode() {
  setTzMode((m) => {
    if (m === "utc") return "local";
    if (m === "local") return "relative";
    return "utc";
  });
}

// Tick signal — updates every second while in relative mode so that
// all formatDate() call sites reactively re-render their countdowns.
const [now, setNow] = createSignal(Date.now());

createRoot(() => {
  createEffect(() => {
    if (tzMode() === "relative") {
      const id = setInterval(() => setNow(Date.now()), 1000);
      onCleanup(() => clearInterval(id));
    }
  });
});

/**
 * Parse an ASN1 GeneralizedTime string ("20270415051336Z") into a Date.
 * Falls back to trying Date.parse for other formats.
 */
function parseAsn1Date(value: string): Date | null {
  // ASN1 format: YYYYMMDDHHmmSSZ (15 chars)
  const m = value.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (m) {
    return new Date(
      Date.UTC(
        parseInt(m[1]),
        parseInt(m[2]) - 1,
        parseInt(m[3]),
        parseInt(m[4]),
        parseInt(m[5]),
        parseInt(m[6]),
      ),
    );
  }
  // Fallback: try native parsing (handles "Apr 15 05:13:36 2027 GMT" etc.)
  const d = new Date(value);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Format a duration into a compact countdown string for future dates.
 *
 * Shows the two most significant non-zero units for readability:
 *   >= 1 year:  "2y 3mo"
 *   >= 1 day:   "45d 12h"
 *   >= 1 hour:  "4h 12m 30s"
 *   >= 1 min:   "12m 30s"
 *   < 1 min:    "45s"
 */
function formatCountdown(target: Date, nowMs: number): string {
  const diffMs = target.getTime() - nowMs;
  if (diffMs <= 0) return "expired";

  const totalSeconds = Math.floor(diffMs / 1000);
  const seconds = totalSeconds % 60;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const minutes = totalMinutes % 60;
  const totalHours = Math.floor(totalMinutes / 60);
  const hours = totalHours % 24;
  const totalDays = Math.floor(totalHours / 24);

  // For periods >= 1 year, use calendar-based months for accuracy
  if (totalDays >= 365) {
    const nowDate = new Date(nowMs);
    let years = target.getUTCFullYear() - nowDate.getUTCFullYear();
    let months = target.getUTCMonth() - nowDate.getUTCMonth();
    if (months < 0) {
      years--;
      months += 12;
    }
    // Adjust if the day hasn't been reached yet this month
    if (target.getUTCDate() < nowDate.getUTCDate()) {
      months--;
      if (months < 0) {
        years--;
        months += 12;
      }
    }
    if (years > 0 && months > 0) return `${years}y ${months}mo`;
    if (years > 0) return `${years}y`;
    return `${months}mo`;
  }

  if (totalDays >= 1) return `${totalDays}d ${hours}h`;
  if (totalHours >= 1) return `${hours}h ${minutes}m ${seconds}s`;
  if (totalMinutes >= 1) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

/**
 * Format a past date as a human-friendly "time ago" string.
 *
 *   < 60s:    "just now"
 *   < 1h:     "X minutes ago"
 *   < 1d:     "X hours ago"
 *   < 30d:    "X days ago"
 *   < 365d:   "X months ago"
 *   >= 1y:    "X years, X months ago" or "X years ago"
 */
function formatTimeAgo(target: Date, nowMs: number): string {
  const diffMs = nowMs - target.getTime();
  if (diffMs < 0) return formatCountdown(target, nowMs);

  const totalSeconds = Math.floor(diffMs / 1000);
  if (totalSeconds < 60) return "just now";

  const totalMinutes = Math.floor(totalSeconds / 60);
  if (totalMinutes < 60) {
    return totalMinutes === 1 ? "1 minute ago" : `${totalMinutes} minutes ago`;
  }

  const totalHours = Math.floor(totalMinutes / 60);
  if (totalHours < 24) {
    return totalHours === 1 ? "1 hour ago" : `${totalHours} hours ago`;
  }

  const totalDays = Math.floor(totalHours / 24);
  if (totalDays < 30) {
    return totalDays === 1 ? "1 day ago" : `${totalDays} days ago`;
  }

  // Calendar-based for months/years
  const nowDate = new Date(nowMs);
  let years = nowDate.getUTCFullYear() - target.getUTCFullYear();
  let months = nowDate.getUTCMonth() - target.getUTCMonth();
  if (months < 0) {
    years--;
    months += 12;
  }
  if (nowDate.getUTCDate() < target.getUTCDate()) {
    months--;
    if (months < 0) {
      years--;
      months += 12;
    }
  }

  if (years >= 1) {
    const yLabel = years === 1 ? "1 year" : `${years} years`;
    if (months > 0) {
      const mLabel = months === 1 ? "1 month" : `${months} months`;
      return `${yLabel}, ${mLabel} ago`;
    }
    return `${yLabel} ago`;
  }

  return months <= 1 ? "1 month ago" : `${months} months ago`;
}

/**
 * Format a date as a relative time string.
 * Future dates use compact countdown; past dates use natural language.
 */
function formatRelativeTime(date: Date, nowMs: number): string {
  if (date.getTime() > nowMs) {
    return formatCountdown(date, nowMs);
  }
  return formatTimeAgo(date, nowMs);
}

/**
 * Format a date string for display.
 *
 * Returns a human-friendly string in UTC, local time, or relative time,
 * depending on the current timezone mode.
 */
export function formatDate(
  value: string | null | undefined,
  mode?: TimeZoneMode,
): string {
  if (!value) return "\u2014";
  const date = parseAsn1Date(value);
  if (!date) return value; // Can't parse — return raw

  const tz = mode ?? tzMode();

  if (tz === "relative") {
    return formatRelativeTime(date, now());
  }

  if (tz === "utc") {
    return date.toLocaleString("en-AU", {
      timeZone: "UTC",
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }) + " UTC";
  }

  return date.toLocaleString("en-AU", {
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short",
  });
}
