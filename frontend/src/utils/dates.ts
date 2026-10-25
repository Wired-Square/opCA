import { formatWhen, useDateModes } from "@wired-square/kit";

/** An ASN.1 GeneralizedTime ("20270415051336Z"), or any form `Date` reads, as a `Date`. */
export function asn1Date(value: string): Date | null {
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
 * A countdown for a future date, or how long ago a past one was:
 *
 *   < 60s:    "just now"
 *   < 1h:     "X minutes ago"
 *   < 1d:     "X hours ago"
 *   < 30d:    "X days ago"
 *   < 365d:   "X months ago"
 *   >= 1y:    "X years, X months ago" or "X years ago"
 */
export function formatRelativeTime(target: Date, nowMs: number): string {
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

/** Full local date and time, e.g. "Tue 29 Sep 2026, 11:57 pm AEST". */
export function formatLocalDateTime(date: Date): string {
  return date.toLocaleString("en-AU", {
    weekday: "short",
    day: "numeric",
    month: "short",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

/** A stored date as text in the current `DateModes` mode: "—" when missing, as stored when unreadable. */
export function useDateText(): (value: string | null | undefined) => string {
  const modes = useDateModes();
  return (value) => {
    if (!value) return "\u2014";
    const at = asn1Date(value);
    return at
      ? formatWhen(at, modes.mode(), { now: modes.now(), locale: modes.locale, relative: modes.relative })
      : value;
  };
}
