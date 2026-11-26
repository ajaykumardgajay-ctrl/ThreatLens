import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Cpu, ShieldAlert, Zap } from 'lucide-react';

interface DeviationRow {
  feature: string;
  observed: number;
  baseline?: number;
  baseline_mean?: number;
  z_score: number;
  detail?: string;
}

export const RiskBadges: React.FC<{
  ruleScore?: number | null;
  mlScore?: number | null;
  combinedRisk?: number | null;
}> = ({ ruleScore = 0, mlScore = 0, combinedRisk = 0 }) => {
  const r = Number(ruleScore ?? 0);
  const m = Number(mlScore ?? 0);
  const c = Number(combinedRisk ?? 0);

  return (
    <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px]">
      <span className="inline-flex items-center gap-1 rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 text-zinc-300">
        <ShieldAlert className="w-3 h-3 text-rose-400" />
        Rule: <strong className="text-zinc-100">{r.toFixed(0)}</strong>
      </span>
      <span className="inline-flex items-center gap-1 rounded border border-amber-500/35 bg-amber-500/10 px-2 py-0.5 text-amber-300">
        <Cpu className="w-3 h-3 text-amber-400" />
        ML: <strong>{m.toFixed(1)}</strong>
      </span>
      <span
        className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 font-semibold ${
          c >= 80
            ? 'border-rose-500/50 bg-rose-500/15 text-rose-300'
            : c >= 55
            ? 'border-amber-500/50 bg-amber-500/15 text-amber-300'
            : 'border-zinc-700 bg-zinc-900 text-zinc-300'
        }`}
      >
        <Zap className="w-3 h-3" />
        Combined Risk: {c.toFixed(1)}
      </span>
    </div>
  );
};

export const MlBreakdownPanel: React.FC<{
  mlScore?: number | null;
  reasons?: string[] | null;
  deviations?: DeviationRow[] | null;
  defaultOpen?: boolean;
}> = ({ mlScore = 0, reasons, deviations, defaultOpen = false }) => {
  const [open, setOpen] = useState(defaultOpen);
  const hasReasons = Boolean(reasons && reasons.length > 0);
  const hasDevs = Boolean(deviations && deviations.length > 0);

  if (!hasReasons && !hasDevs) return null;

  return (
    <div className="rounded border border-zinc-800 bg-zinc-950/80 overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center justify-between px-3 py-2 text-left text-[11px] font-medium text-amber-300 hover:bg-zinc-900/70 transition"
      >
        <span className="inline-flex items-center gap-1.5">
          {open ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          Why ML Flagged This (Feature Deviations)
        </span>
        <span className="font-mono text-[10px] text-zinc-400">
          ML Score {Number(mlScore ?? 0).toFixed(1)}/100
        </span>
      </button>

      {open && (
        <div className="border-t border-zinc-800 p-3 space-y-2.5 text-[11px]">
          {hasReasons && (
            <ul className="space-y-1 text-zinc-200 list-disc list-inside">
              {reasons!.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
          )}

          {hasDevs && (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-[10px]">
                <thead className="text-zinc-500 border-b border-zinc-800">
                  <tr>
                    <th className="py-1 pr-2">Feature</th>
                    <th className="py-1 pr-2">Observed</th>
                    <th className="py-1 pr-2">Baseline</th>
                    <th className="py-1 pr-2">Z-Score</th>
                    <th className="py-1">Context</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {deviations!.slice(0, 6).map((d) => {
                    const baseVal = d.baseline ?? d.baseline_mean ?? 0;
                    const highZ = Math.abs(d.z_score) >= 2.0;
                    return (
                      <tr key={d.feature}>
                        <td className="py-1 pr-2 text-zinc-200">{d.feature}</td>
                        <td className="py-1 pr-2 text-amber-300">{d.observed}</td>
                        <td className="py-1 pr-2 text-zinc-400">{baseVal}</td>
                        <td
                          className={`py-1 pr-2 font-semibold ${
                            highZ ? 'text-rose-400' : 'text-zinc-300'
                          }`}
                        >
                          {d.z_score >= 0 ? `+${d.z_score}` : d.z_score}
                        </td>
                        <td className="py-1 text-zinc-400 font-sans">{d.detail || '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
