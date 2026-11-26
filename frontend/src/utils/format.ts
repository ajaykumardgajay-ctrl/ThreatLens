import type { SeverityType } from '../types/tracepoint';

export function formatUtcTime(iso: string): string {
  if (!iso) return '—';
  return iso.replace('T', ' ').replace('Z', ' UTC');
}

export function formatShortTime(iso: string): string {
  if (!iso) return '—';
  return iso.slice(11, 19);
}

export function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(1)} MB`;
  const kb = bytes / 1024;
  if (kb >= 1) return `${kb.toFixed(1)} KB`;
  return `${bytes} B`;
}

export function severityBadgeClass(sev: SeverityType | string): string {
  switch (sev) {
    case 'critical':
      return 'bg-rose-500/15 text-rose-400 border-rose-500/40';
    case 'high':
      return 'bg-red-500/15 text-red-400 border-red-500/40';
    case 'medium':
      return 'bg-amber-500/15 text-amber-300 border-amber-500/40';
    default:
      return 'bg-zinc-800 text-zinc-300 border-zinc-700';
  }
}
