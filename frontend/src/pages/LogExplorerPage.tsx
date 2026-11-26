import React, { useEffect, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Code2, Filter, Search } from 'lucide-react';
import { MlBreakdownPanel, RiskBadges } from '../components/MlBreakdownPanel';
import { api } from '../services/api';
import type { CanonicalEvent, MetricsResponse } from '../types/tracepoint';
import { formatBytes } from '../utils/format';

interface LogExplorerPageProps {
  metrics: MetricsResponse | null;
  refreshVersion: number;
}

const SOURCE_OPTIONS = ['', 'auth', 'web', 'firewall', 'windows', 'system', 'proxy'];

export const LogExplorerPage: React.FC<LogExplorerPageProps> = ({ metrics, refreshVersion }) => {
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [sortBy, setSortBy] = useState<'timestamp' | 'final_event_risk' | 'ml_anomaly_score'>('timestamp');
  const [query, setQuery] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [events, setEvents] = useState<CanonicalEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<CanonicalEvent | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    const params: Record<string, string> = { limit: '250', sort_by: sortBy };
    if (sourceFilter) params.source_type = sourceFilter;
    if (statusFilter) params.status = statusFilter;
    if (query.trim()) {
      params.q = query.trim();
      if (useRegex) params.regex = 'true';
    }

    api
      .getLogs(params)
      .then((res) => {
        if (!active) return;
        setEvents(res.events);
        setTotal(res.total);
        if (res.events.length > 0) {
          setSelected((prev) =>
            prev && res.events.some((e) => e.event_id === prev.event_id) ? prev : res.events[0]
          );
        } else {
          setSelected(null);
        }
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : 'Query failed');
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [sourceFilter, statusFilter, sortBy, query, useRegex, refreshVersion]);

  return (
    <div className="space-y-4">
      {/* Timeline Histogram */}
      {metrics && metrics.activity_series.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
              Event &amp; Failure Distribution Over Time (UTC)
            </span>
            <span className="font-mono text-[11px] text-zinc-400">
              {metrics.total_events_processed.toLocaleString()} total events
            </span>
          </div>
          <div className="h-32">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={metrics.activity_series}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" vertical={false} />
                <XAxis
                  dataKey="hour"
                  tickFormatter={(v) => String(v).slice(11, 16)}
                  stroke="#71717a"
                  fontSize={10}
                />
                <YAxis stroke="#71717a" fontSize={10} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#09090b',
                    borderColor: '#3f3f46',
                    fontSize: '11px',
                  }}
                />
                <Bar dataKey="total" name="Total" fill="#f59e0b" radius={[2, 2, 0, 0]} />
                <Bar dataKey="failures" name="Failures/Blocks" fill="#f43f5e" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Search & Facets */}
      <div className="rounded-lg border border-zinc-800 bg-[#111114] p-3 flex flex-wrap items-center gap-2.5">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={
              useRegex
                ? 'Regex filter (e.g. 185\\.220\\.101\\.4|usermod|UNION\\s+SELECT)...'
                : 'Search raw logs, IP, username, resource, action...'
            }
            className="w-full rounded border border-zinc-800 bg-zinc-950 pl-8 pr-3 py-1.5 font-mono text-xs text-zinc-100 placeholder-zinc-600 focus:border-amber-500 focus:outline-none"
          />
        </div>

        <button
          onClick={() => setUseRegex((v) => !v)}
          className={`inline-flex items-center gap-1 rounded border px-2.5 py-1.5 font-mono text-[11px] transition ${
            useRegex
              ? 'border-amber-500/60 bg-amber-500/15 text-amber-300'
              : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
          }`}
          title="Toggle regular expression matching"
        >
          <Code2 className="w-3.5 h-3.5" />
          .* Regex
        </button>

        <div className="flex items-center gap-1.5 flex-wrap">
          <Filter className="w-3.5 h-3.5 text-zinc-500" />
          {SOURCE_OPTIONS.map((s) => (
            <button
              key={s || 'all'}
              onClick={() => setSourceFilter(s)}
              className={`px-2 py-1 rounded text-[11px] font-mono border transition ${
                sourceFilter === s
                  ? 'border-amber-500/60 bg-amber-500/15 text-amber-300'
                  : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:text-zinc-200'
              }`}
            >
              {s || 'all'}
            </button>
          ))}
        </div>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200"
        >
          <option value="">All Outcomes</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
        </select>

        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
          className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs text-amber-300 font-mono"
        >
          <option value="timestamp">Sort: Chronological</option>
          <option value="final_event_risk">Sort: Combined Risk</option>
          <option value="ml_anomaly_score">Sort: ML Score</option>
        </select>

        <span className="font-mono text-[11px] text-zinc-400 ml-auto">
          {loading ? 'Querying...' : `${events.length} / ${total} matched`}
        </span>
      </div>

      {error && (
        <div className="rounded border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Split Table + Field Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-7 rounded-lg border border-zinc-800 bg-[#111114] overflow-hidden">
          <div className="max-h-[540px] overflow-y-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="sticky top-0 bg-zinc-950 text-[10px] uppercase tracking-wider text-zinc-400 border-b border-zinc-800">
                <tr>
                  <th className="px-3 py-2.5">Timestamp</th>
                  <th className="px-3 py-2.5">Source</th>
                  <th className="px-3 py-2.5">User</th>
                  <th className="px-3 py-2.5">Src / Dst IP</th>
                  <th className="px-3 py-2.5">Action / Resource</th>
                  <th className="px-3 py-2.5">Risk</th>
                  <th className="px-3 py-2.5">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70">
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-10 text-center text-zinc-500">
                      No events match the current filter. Ingest logs in the Analyze &amp; Ingest tab.
                    </td>
                  </tr>
                ) : (
                  events.map((ev) => (
                    <tr
                      key={ev.event_id}
                      onClick={() => setSelected(ev)}
                      className={`cursor-pointer hover:bg-zinc-900/80 transition ${
                        selected?.event_id === ev.event_id ? 'bg-amber-500/10' : ''
                      }`}
                    >
                      <td className="px-3 py-2 font-mono text-zinc-400 whitespace-nowrap">
                        {ev.timestamp.slice(11, 19)}Z
                      </td>
                      <td className="px-3 py-2 font-mono text-amber-300">{ev.source_type}</td>
                      <td className="px-3 py-2 font-mono text-zinc-100">{ev.user}</td>
                      <td className="px-3 py-2 font-mono text-zinc-300">
                        {ev.src_ip || ev.dest_ip || '—'}
                      </td>
                      <td className="px-3 py-2 font-mono text-zinc-300 max-w-[190px] truncate">
                        {ev.action} {ev.resource ? `(${ev.resource})` : ''}
                      </td>
                      <td className="px-3 py-2 font-mono whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            ev.final_event_risk >= 70
                              ? 'bg-rose-500/15 text-rose-400'
                              : ev.final_event_risk >= 40
                              ? 'bg-amber-500/15 text-amber-300'
                              : 'text-zinc-500'
                          }`}
                        >
                          {ev.final_event_risk.toFixed(0)}
                        </span>
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                            ev.status === 'failure'
                              ? 'bg-rose-500/15 text-rose-400'
                              : ev.status === 'success'
                              ? 'bg-emerald-500/15 text-emerald-400'
                              : 'bg-zinc-800 text-zinc-400'
                          }`}
                        >
                          {ev.status}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="xl:col-span-5 rounded-lg border border-zinc-800 bg-[#111114] p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 mb-3">
            Parsed Fields &amp; Raw Line Inspector
          </h3>
          {selected ? (
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono font-semibold text-amber-400">{selected.event_id}</span>
                <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                  {selected.source_type}
                </span>
              </div>
              <RiskBadges
                ruleScore={selected.rule_score}
                mlScore={selected.ml_anomaly_score}
                combinedRisk={selected.final_event_risk}
              />
              <MlBreakdownPanel
                mlScore={selected.ml_anomaly_score}
                reasons={selected.ml_reasons}
                deviations={selected.ml_feature_deviations}
              />
              <div>
                <div className="text-[10px] uppercase text-zinc-500 mb-1">Original Raw Log Line</div>
                <pre className="rounded border border-zinc-800 bg-black p-3 font-mono text-[11px] text-amber-200 whitespace-pre-wrap break-all">
                  {selected.raw_log}
                </pre>
              </div>
              <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-500">Timestamp</div>
                  <div className="text-zinc-100">{selected.timestamp}</div>
                </div>
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-500">Hostname</div>
                  <div className="text-zinc-100">{selected.hostname}</div>
                </div>
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-500">Source IP</div>
                  <div className="text-zinc-100">{selected.src_ip || '—'}</div>
                </div>
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-500">Destination IP</div>
                  <div className="text-zinc-100">{selected.dest_ip || '—'}</div>
                </div>
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-500">User / Target</div>
                  <div className="text-zinc-100">
                    {selected.user}
                    {selected.target_user ? ` -> ${selected.target_user}` : ''}
                  </div>
                </div>
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800">
                  <div className="text-[10px] text-zinc-500">Bytes Out / Session</div>
                  <div className="text-zinc-100">
                    {formatBytes(selected.bytes_out)} / {selected.session_id || '—'}
                  </div>
                </div>
                <div className="rounded bg-zinc-950 p-2 border border-zinc-800 col-span-2">
                  <div className="text-[10px] text-zinc-500">Action &amp; Resource</div>
                  <div className="text-zinc-100 break-all">
                    {selected.action} — {selected.resource || '—'}
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-zinc-500 py-8 text-center">
              Click any log row to inspect normalized fields and original raw line.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
