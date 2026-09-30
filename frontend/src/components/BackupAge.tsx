import { Show } from "solid-js";
import { formatLocalDateTime, formatTimeAgo } from "../utils/dates";

const STALE_BACKUP_DAYS = 7;

const DAY_MS = 24 * 60 * 60 * 1000;

function backupAgeDays(takenAt: string): number {
  return Math.floor((Date.now() - new Date(takenAt).getTime()) / DAY_MS);
}

export function backupAgePhrase(takenAt: string): string {
  return formatTimeAgo(new Date(takenAt), Date.now());
}

/** Age first ("3 days ago"), then the exact local time, flagging stale copies. */
export default function BackupAge(props: { takenAt: string }) {
  const days = () => backupAgeDays(props.takenAt);
  return (
    <span>
      <strong>{backupAgePhrase(props.takenAt)}</strong>{" "}
      <Show when={days() >= STALE_BACKUP_DAYS}>
        <span class="status-badge status-expiring">{days()} days old</span>{" "}
      </Show>
      <span class="text-muted text-sm">{formatLocalDateTime(new Date(props.takenAt))}</span>
    </span>
  );
}
