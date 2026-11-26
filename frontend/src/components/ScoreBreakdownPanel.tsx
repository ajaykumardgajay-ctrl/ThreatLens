import React from 'react';
import { Info } from 'lucide-react';
import type { RiskScoreBreakdown } from '../types/tracepoint';
import { severityBadgeClass } from '../utils/format';

export const ScoreBreakdownPanel: React.FC<{ breakdown: RiskScoreBreakdown }> = ({ breakdown }) => {
  return (
    <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 pb-3 mb-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
            Risk Prioritisation Breakdown
          </h3>
          <p className="text-[11px] text-zinc-400 mt-0.5 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-amber-400 shrink-0" />
            {breakdown.scoring_note}
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <span
            className={`px-2 py-0.5 rounded border text-[11px] font-semibold uppercase ${severityBadgeClass(
              breakdown.severity
            )}`}
          >
            {breakdown.severity}
          </span>
          <div className="font-mono text-xl font-bold text-zinc-100">
            {breakdown.total_score}
            <span className="text-xs font-normal text-zinc-400">/{breakdown.max_score}</span>
          </div>
        </div>
      </div>

      <div className="h-2.5 w-full rounded-full bg-zinc-950 border border-zinc-800 overflow-hidden flex mb-4">
        {breakdown.contributions
          .filter((c) => c.points > 0)
          .map((c, i) => {
            const colors = [
              'bg-rose-500',
              'bg-red-500',
              'bg-amber-500',
              'bg-amber-400',
              'bg-orange-400',
            ];
            return (
              <div
                key={c.category}
                style={{ width: `${c.points}%` }}
                className={`${colors[i % colors.length]} h-full border-r border-zinc-950`}
                title={`${c.detector_name}: +${c.points}`}
              />
            );
          })}
      </div>

      <div className="space-y-2">
        {breakdown.contributions.map((c) => (
          <div
            key={c.category}
            className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded border border-zinc-800 bg-zinc-950/70 px-3 py-2"
          >
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-xs font-medium text-zinc-100">{c.detector_name}</span>
                {c.suppressed_duplicates > 0 && (
                  <span className="text-[10px] rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 text-zinc-400">
                    {c.suppressed_duplicates} duplicate suppressed
                  </span>
                )}
              </div>
              <div className="text-[11px] text-zinc-400 mt-0.5">{c.rationale}</div>
              <div className="mt-1 flex flex-wrap gap-1">
                {c.supporting_event_ids.slice(0, 4).map((eid) => (
                  <span
                    key={eid}
                    className="font-mono text-[10px] px-1.5 py-0.5 bg-zinc-900 border border-zinc-800 rounded text-amber-300"
                  >
                    {eid}
                  </span>
                ))}
                {c.supporting_event_ids.length > 4 && (
                  <span className="font-mono text-[10px] text-zinc-500">
                    +{c.supporting_event_ids.length - 4} more
                  </span>
                )}
              </div>
            </div>
            <div className="flex sm:flex-col items-end justify-between shrink-0">
              <span
                className={`font-mono text-sm font-bold ${
                  c.points > 0 ? 'text-rose-400' : 'text-zinc-500'
                }`}
              >
                +{c.points} pts
              </span>
              <span className="text-[10px] font-mono text-zinc-400">
                conf {Math.round(c.confidence * 100)}%
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
