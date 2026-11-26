import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Database,
  FileUp,
  Flame,
  Play,
  RotateCcw,
  Sparkles,
  Upload,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  AnalyzerSummary,
  CanonicalEvent,
  IngestionReport,
  MetricsResponse,
  SamplePreset,
} from '../types/tracepoint';
import { formatUtcTime } from '../utils/format';

interface AnalyzeWorkbenchPageProps {
  presets: SamplePreset[];
  summary: AnalyzerSummary | null;
  metrics: MetricsResponse | null;
  report: IngestionReport | null;
  onReportChange: (rep: IngestionReport | null) => void;
  topEvents: CanonicalEvent[];
  onDataUpdated: () => Promise<void>;
  onNavigateTab: (tab: 'analyze' | 'explorer' | 'threats' | 'reports') => void;
}

export const AnalyzeWorkbenchPage: React.FC<AnalyzeWorkbenchPageProps> = ({
  presets,
  summary,
  metrics,
  report,
  onReportChange: setReport,
  topEvents,
  onDataUpdated,
  onNavigateTab,
}) => {
  const [logFormat, setLogFormat] = useState('auto');
  const [appendMode, setAppendMode] = useState(false);
  const [rawText, setRawText] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runUpload = async (file: File) => {
    setBusy(true);
    setError(null);
    try {
      const rep = await api.uploadLogs(file, logFormat, !appendMode);
      setReport(rep);
      await onDataUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed');
    } finally {
      setBusy(false);
    }
  };

  const handleAnalyzeText = async () => {
    if (!rawText.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const rep = await api.analyzeRawLogs(rawText, logFormat, !appendMode);
      setReport(rep);
      await onDataUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setBusy(false);
    }
  };

  const handlePreset = async (id: string) => {
    setBusy(true);
    setError(null);
    try {
      const rep = await api.loadPreset(id);
      setReport(rep);
      await onDataUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load preset');
    } finally {
      setBusy(false);
    }
  };

  const handleFullDemo = async () => {
    setBusy(true);
    setError(null);
    try {
      const rep = await api.loadDemo();
      setReport(rep);
      await onDataUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load enterprise demo');
    } finally {
      setBusy(false);
    }
  };

  const handleReset = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.resetDemo();
      setReport(null);
      await onDataUpdated();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Hero Strip: Dropzone + Quick Presets */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-7 rounded-lg border border-zinc-800 bg-[#111114] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                <FileUp className="w-4 h-4 text-amber-400" />
                Ingest &amp; Parse Security Logs
              </h2>
              <p className="text-xs text-zinc-400 mt-0.5">
                Supports OpenSSH/Auth, Apache/Nginx, UFW/iptables/ASA Firewall, Windows Security/Sysmon, OS Audit/Sudo, JSON/NDJSON &amp; CSV
              </p>
            </div>
            <div className="flex items-center gap-2">
              <label className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 cursor-pointer mr-1">
                <input
                  type="checkbox"
                  checked={appendMode}
                  onChange={(e) => setAppendMode(e.target.checked)}
                  className="rounded border-zinc-700 bg-zinc-950 text-amber-500"
                />
                Append to existing
              </label>
              <select
                value={logFormat}
                onChange={(e) => setLogFormat(e.target.value)}
                className="rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1.5 text-xs text-zinc-200 focus:border-amber-500 focus:outline-none"
              >
              <option value="auto">Auto-detect format</option>
              <option value="ssh_auth">Linux SSH / Auth</option>
              <option value="web_access">Web Access (Apache/Nginx)</option>
              <option value="firewall">Firewall (UFW / iptables / ASA)</option>
              <option value="windows_event">Windows Event / Sysmon</option>
              <option value="os_audit">OS Audit / Sudo / Netflow</option>
              <option value="json">JSON / NDJSON</option>
              <option value="csv">CSV</option>
              <option value="txt">Mixed Raw TXT</option>
              </select>
            </div>
          </div>

          <label
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const f = e.dataTransfer.files?.[0];
              if (f) runUpload(f);
            }}
            className={`flex flex-col items-center justify-center rounded-lg border-2 border-dashed p-6 cursor-pointer transition ${
              dragOver
                ? 'border-amber-400 bg-amber-500/10'
                : 'border-zinc-800 bg-zinc-950/70 hover:border-amber-500/50'
            }`}
          >
            <Upload className="w-6 h-6 text-amber-400 mb-2" />
            <span className="text-xs font-medium text-zinc-100">
              Drag &amp; drop any log file here, or click to browse
            </span>
            <span className="text-[11px] text-zinc-500 mt-1">
              Every raw line is preserved; malformed entries are surfaced without crashing
            </span>
            <input
              type="file"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) runUpload(f);
                e.target.value = '';
              }}
              className="hidden"
            />
          </label>

          <div>
            <div className="flex items-center justify-between text-[11px] text-zinc-400 mb-1.5">
              <span>Or paste raw log lines to analyze immediately:</span>
              <button
                onClick={handleReset}
                disabled={busy}
                className="inline-flex items-center gap-1 text-zinc-400 hover:text-rose-400 transition"
              >
                <RotateCcw className="w-3 h-3" /> Clear Workspace
              </button>
            </div>
            <textarea
              rows={5}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder={`2026-11-25T14:04:03Z prod-bastion-01 sshd[4190]: Accepted password for admin_01 from 185.220.101.4 port 51900 ssh2 geo="Frankfurt, DE" session=sess-4190`}
              className="w-full rounded border border-zinc-800 bg-zinc-950 p-3 font-mono text-[11px] text-zinc-200 placeholder-zinc-600 focus:border-amber-500 focus:outline-none"
            />
            <div className="mt-2.5 flex items-center justify-end gap-2">
              <button
                onClick={handleAnalyzeText}
                disabled={busy || !rawText.trim()}
                className="inline-flex items-center gap-1.5 rounded-md bg-amber-500 hover:bg-amber-400 disabled:opacity-40 px-4 py-1.5 text-xs font-semibold text-zinc-950 transition"
              >
                <Play className="w-3.5 h-3.5" />
                {busy ? 'Analyzing...' : 'Analyze Pasted Logs'}
              </button>
            </div>
          </div>
        </div>

        {/* Sample Datasets & Presets */}
        <div className="xl:col-span-5 rounded-lg border border-zinc-800 bg-[#111114] p-5 flex flex-col justify-between space-y-4">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-400" />
                One-Click Sample Log Scenarios
              </h2>
              <span className="font-mono text-[10px] text-zinc-500">RESETS &amp; ANALYZES</span>
            </div>

            <div className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-rose-300 flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5 text-rose-400" />
                  Enterprise Multi-Stage Stream (1,188 Logs)
                </span>
                <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-rose-500/15 text-rose-300">
                  INC-2026-041
                </span>
              </div>
              <p className="text-[11px] text-zinc-400">
                Mixed normal corporate traffic + SSH brute force, impossible travel, privilege pivot, payroll file access &amp; 418 MB exfiltration.
              </p>
              <button
                onClick={handleFullDemo}
                disabled={busy}
                className="w-full rounded bg-rose-600 hover:bg-rose-500 disabled:opacity-50 py-1.5 text-xs font-semibold text-white transition"
              >
                {busy ? 'Running Pipeline...' : 'Load 1,188-Event Enterprise Dataset'}
              </button>
            </div>

            <div className="space-y-2">
              {presets.map((p) => (
                <button
                  key={p.id}
                  onClick={() => handlePreset(p.id)}
                  disabled={busy}
                  className="w-full text-left rounded-md border border-zinc-800 bg-zinc-950/70 hover:border-amber-500/50 p-3 transition group"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-zinc-100 group-hover:text-amber-300">
                      {p.name}
                    </span>
                    <span className="font-mono text-[10px] text-zinc-500 uppercase">{p.format}</span>
                  </div>
                  <p className="text-[11px] text-zinc-400 mt-0.5">{p.description}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-xs text-rose-300">
          {error}
        </div>
      )}

      {/* Parse Result Banner */}
      {report && (
        <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div
              className={`flex items-center gap-2 text-xs font-semibold ${
                report.parsed_count === 0 ? 'text-amber-400' : 'text-emerald-400'
              }`}
            >
              {report.parsed_count === 0 ? (
                <AlertTriangle className="w-4 h-4" />
              ) : (
                <CheckCircle2 className="w-4 h-4" />
              )}
              <span>
                {report.filename ? <strong className="font-mono">{report.filename}</strong> : 'Ingested'} &mdash;{' '}
                Parsed {report.parsed_count} of {report.total_lines} lines ({report.format_detected}) &middot;{' '}
                {report.findings_generated} finding(s) &middot; {report.incidents_detected} incident(s)
              </span>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => onNavigateTab('explorer')}
                className="rounded border border-zinc-700 bg-zinc-900 hover:border-zinc-500 px-3 py-1 text-xs text-zinc-200"
              >
                Browse Logs
              </button>
              <button
                onClick={() => onNavigateTab('threats')}
                className="rounded bg-amber-500 hover:bg-amber-400 px-3 py-1 text-xs font-semibold text-zinc-950"
              >
                Inspect Threats &amp; Chains
              </button>
            </div>
          </div>
          {report.errors.length > 0 && (
            <div className="rounded border border-amber-500/30 bg-amber-500/5 p-3 space-y-1 max-h-32 overflow-y-auto">
              <div className="text-[10px] font-semibold uppercase text-amber-400">
                Skipped / Malformed Lines ({report.skipped_count})
              </div>
              {report.errors.map((err, i) => (
                <div key={i} className="font-mono text-[10px] text-zinc-400">
                  Line {err.line_number}: {err.reason} — {err.raw_line}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Instant Workspace Summary */}
      {summary && summary.total_events > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
              <Database className="w-3.5 h-3.5 text-amber-400" />
              Telemetry Breakdown
            </div>
            <div className="font-mono text-xs text-zinc-300">
              {formatUtcTime(summary.time_range.start || '')} &rarr;{' '}
              {formatUtcTime(summary.time_range.end || '')}
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {Object.entries(summary.source_counts).map(([src, cnt]) => (
                <span
                  key={src}
                  className="rounded border border-zinc-800 bg-zinc-950 px-2 py-1 font-mono text-[11px] text-zinc-200"
                >
                  {src}: <span className="text-amber-400 font-semibold">{cnt}</span>
                </span>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              Detection Summary
            </div>
            <div className="grid grid-cols-3 gap-2 pt-1 font-mono">
              <div className="rounded bg-zinc-950 border border-zinc-800 p-2">
                <div className="text-[10px] text-zinc-500">Rules</div>
                <div className="text-base font-bold text-rose-400">{metrics?.rule_findings_count ?? 0}</div>
              </div>
              <div className="rounded bg-zinc-950 border border-zinc-800 p-2">
                <div className="text-[10px] text-zinc-500">ML Outliers</div>
                <div className="text-base font-bold text-amber-400">{metrics?.ml_findings_count ?? 0}</div>
              </div>
              <div className="rounded bg-zinc-950 border border-zinc-800 p-2">
                <div className="text-[10px] text-zinc-500">IOCs</div>
                <div className="text-base font-bold text-zinc-100">{summary.iocs.length}</div>
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2">
            <div className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
              Top Targeted Hosts
            </div>
            <div className="space-y-1">
              {summary.top_hosts.slice(0, 4).map((h) => (
                <div
                  key={h.hostname}
                  className="flex items-center justify-between font-mono text-xs bg-zinc-950 border border-zinc-800/80 px-2.5 py-1 rounded"
                >
                  <span className="text-zinc-200">{h.hostname}</span>
                  <span className="text-amber-400">{h.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Loaded Events Preview (Top Ranked by Hybrid Risk) */}
      {summary && summary.total_events > 0 && topEvents.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-[#111114] overflow-hidden">
          <div className="px-4 py-2.5 border-b border-zinc-800 flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
              Active Workspace Preview — Top Ranked Events ({summary.total_events} total)
            </span>
            <button
              onClick={() => onNavigateTab('explorer')}
              className="text-[11px] font-mono text-amber-400 hover:text-amber-300"
            >
              Open Full Log Explorer &rarr;
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[11px]">
              <thead className="bg-zinc-950 text-[10px] uppercase text-zinc-500 border-b border-zinc-800">
                <tr>
                  <th className="px-3 py-2">Timestamp</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">Src IP</th>
                  <th className="px-3 py-2">Action / Resource</th>
                  <th className="px-3 py-2">Rule / ML / Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/70 font-mono">
                {topEvents.map((ev) => (
                  <tr key={ev.event_id} className="hover:bg-zinc-900/60">
                    <td className="px-3 py-2 text-zinc-400 whitespace-nowrap">{ev.timestamp}</td>
                    <td className="px-3 py-2 text-amber-300">{ev.source_type}</td>
                    <td className="px-3 py-2 text-zinc-100">{ev.user}</td>
                    <td className="px-3 py-2 text-zinc-300">{ev.src_ip || ev.dest_ip || '—'}</td>
                    <td className="px-3 py-2 text-zinc-300 max-w-xs truncate">
                      {ev.action} {ev.resource ? `(${ev.resource})` : ''}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <span className="text-zinc-400">R:{ev.rule_score.toFixed(0)}</span>{' '}
                      <span className="text-amber-300">ML:{ev.ml_anomaly_score.toFixed(0)}</span>{' '}
                      <span className="text-rose-400 font-semibold">Risk:{ev.final_event_risk.toFixed(0)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
