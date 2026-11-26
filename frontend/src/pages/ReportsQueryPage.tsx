import React, { useEffect, useState } from 'react';
import { Bot, Cpu, Download, FileText, Save, Send, Sliders } from 'lucide-react';
import { api } from '../services/api';
import type {
  AnalyzerSummary,
  IncidentDetail,
  InvestigationResponse,
  RuntimeSettings,
} from '../types/tracepoint';

interface ReportsQueryPageProps {
  summary: AnalyzerSummary | null;
  incidentDetail: IncidentDetail | null;
  onDataUpdated: () => Promise<void>;
}

const QUICK_QUESTIONS = [
  'What was the initial entry point?',
  'Which account was compromised?',
  'Which systems were accessed after privilege escalation?',
  'What evidence supports the exfiltration finding?',
  'Why is this incident classified as critical?',
  'Show all raw logs associated with this incident.',
];

export const ReportsQueryPage: React.FC<ReportsQueryPageProps> = ({
  summary,
  incidentDetail,
  onDataUpdated,
}) => {
  const [question, setQuestion] = useState('');
  const [answers, setAnswers] = useState<InvestigationResponse[]>([]);
  const [loadingQa, setLoadingQa] = useState(false);
  const [settings, setSettings] = useState<RuntimeSettings | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    api.getSettings().then(setSettings).catch(() => {});
  }, []);

  const ask = async (qText: string) => {
    if (!incidentDetail || !qText.trim()) return;
    setLoadingQa(true);
    try {
      const res = await api.investigate(incidentDetail.incident_id, qText.trim());
      setAnswers((prev) => [res, ...prev]);
      setQuestion('');
    } finally {
      setLoadingQa(false);
    }
  };

  const saveSettings = async () => {
    if (!settings) return;
    setStatusMsg(null);
    const res = await api.updateSettings(settings);
    setSettings(res.settings);
    await onDataUpdated();
    setStatusMsg('Detection thresholds updated and findings recomputed.');
  };

  const retrainMl = async () => {
    setStatusMsg(null);
    const res = await api.retrainMl();
    await onDataUpdated();
    setStatusMsg(`Isolation Forest retrained on ${String(res.training.training_samples)} baseline samples.`);
  };

  return (
    <div className="space-y-5">
      {/* Exportable Reports */}
      <div className="rounded-lg border border-zinc-800 bg-[#111114] p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 flex items-center gap-2">
            <FileText className="w-4 h-4 text-amber-400" />
            Export Security Audit &amp; Incident Report
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            Download extracted IOCs, reconstructed timelines, findings, or normalized canonical events.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <a
            href={api.exportUrl('pdf')}
            download
            className="inline-flex items-center gap-1.5 rounded bg-amber-500 hover:bg-amber-400 px-3.5 py-2 text-xs font-semibold text-zinc-950 transition"
          >
            <Download className="w-3.5 h-3.5" /> PDF Report (.pdf)
          </a>
          <a
            href={api.exportUrl('json')}
            download
            className="inline-flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-950 hover:border-zinc-500 px-3.5 py-2 text-xs font-medium text-zinc-200 transition"
          >
            <Download className="w-3.5 h-3.5" /> Full JSON (.json)
          </a>
          <a
            href={api.exportUrl('csv')}
            download
            className="inline-flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-950 hover:border-zinc-500 px-3.5 py-2 text-xs font-medium text-zinc-200 transition"
          >
            <Download className="w-3.5 h-3.5" /> Normalized Events (.csv)
          </a>
        </div>
      </div>

      {/* Analyst Query Assistant */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-7 rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <Bot className="w-4 h-4 text-amber-400" />
              Evidence-Grounded Incident Query
            </h3>
            {incidentDetail && (
              <span className="font-mono text-xs text-amber-300">{incidentDetail.incident_id}</span>
            )}
          </div>

          {!incidentDetail ? (
            <div className="text-xs text-zinc-500 py-6 text-center">
              No correlated incident selected yet. Ingest logs with suspicious activity to query incident evidence.
            </div>
          ) : (
            <>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  ask(question);
                }}
                className="flex gap-2"
              >
                <input
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder={`Ask about ${incidentDetail.incident_id}...`}
                  className="flex-1 rounded border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-100 placeholder-zinc-600 focus:border-amber-500 focus:outline-none"
                />
                <button
                  type="submit"
                  disabled={loadingQa || !question.trim()}
                  className="inline-flex items-center gap-1.5 rounded bg-amber-500 hover:bg-amber-400 disabled:opacity-40 px-4 py-2 text-xs font-semibold text-zinc-950"
                >
                  <Send className="w-3.5 h-3.5" /> Ask
                </button>
              </form>

              <div className="flex flex-wrap gap-1.5">
                {QUICK_QUESTIONS.map((q) => (
                  <button
                    key={q}
                    onClick={() => ask(q)}
                    disabled={loadingQa}
                    className="rounded border border-zinc-800 bg-zinc-950 hover:border-amber-500/40 hover:text-amber-300 px-2.5 py-1 text-[11px] text-zinc-400 transition"
                  >
                    {q}
                  </button>
                ))}
              </div>

              <div className="space-y-2.5 max-h-[380px] overflow-y-auto pt-1">
                {answers.map((a, i) => (
                  <div key={i} className="rounded border border-zinc-800 bg-zinc-950 p-3 space-y-2">
                    <div className="flex items-center justify-between text-xs font-semibold text-amber-300">
                      <span>{a.question}</span>
                      <span className="font-mono text-[10px] uppercase text-zinc-500">{a.mode}</span>
                    </div>
                    <pre className="font-sans text-xs text-zinc-200 whitespace-pre-wrap leading-relaxed">
                      {a.answer}
                    </pre>
                    <div className="flex flex-wrap gap-1">
                      {a.cited_event_ids.map((eid) => (
                        <span
                          key={eid}
                          className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-amber-300"
                        >
                          {eid}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Threshold Tuning & ML Baseline */}
        <div className="xl:col-span-5 rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-2.5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <Sliders className="w-4 h-4 text-amber-400" />
              Analyzer Thresholds &amp; ML
            </h3>
            <button
              onClick={retrainMl}
              className="inline-flex items-center gap-1 rounded border border-zinc-700 bg-zinc-950 hover:border-amber-500/50 px-2.5 py-1 text-[11px] text-amber-300"
            >
              <Cpu className="w-3.5 h-3.5" /> Retrain ML
            </button>
          </div>

          {settings && (
            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2.5">
                <label>
                  <span className="text-[11px] text-zinc-400">Brute Force Threshold</span>
                  <input
                    type="number"
                    value={settings.brute_force_threshold}
                    onChange={(e) =>
                      setSettings({ ...settings, brute_force_threshold: Number(e.target.value) })
                    }
                    className="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 font-mono text-zinc-100"
                  />
                </label>
                <label>
                  <span className="text-[11px] text-zinc-400">Brute Force Window (s)</span>
                  <input
                    type="number"
                    value={settings.brute_force_window_seconds}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        brute_force_window_seconds: Number(e.target.value),
                      })
                    }
                    className="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 font-mono text-zinc-100"
                  />
                </label>
                <label>
                  <span className="text-[11px] text-zinc-400">Travel Speed (km/h)</span>
                  <input
                    type="number"
                    value={settings.impossible_travel_speed_kmh}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        impossible_travel_speed_kmh: Number(e.target.value),
                      })
                    }
                    className="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 font-mono text-zinc-100"
                  />
                </label>
                <label>
                  <span className="text-[11px] text-zinc-400">Correlation Window (m)</span>
                  <input
                    type="number"
                    value={settings.correlation_window_minutes}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        correlation_window_minutes: Number(e.target.value),
                      })
                    }
                    className="mt-1 w-full rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 font-mono text-zinc-100"
                  />
                </label>
                <label className="col-span-2">
                  <div className="flex items-center justify-between text-[11px] text-zinc-400">
                    <span>ML Anomaly Threshold</span>
                    <span className="font-mono text-amber-300">{settings.ml_anomaly_threshold}</span>
                  </div>
                  <input
                    type="range"
                    min={35}
                    max={95}
                    step={5}
                    value={settings.ml_anomaly_threshold}
                    onChange={(e) =>
                      setSettings({
                        ...settings,
                        ml_anomaly_threshold: Number(e.target.value),
                      })
                    }
                    className="mt-1 w-full accent-amber-500 cursor-pointer"
                  />
                </label>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={saveSettings}
                  className="inline-flex items-center gap-1.5 rounded bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 text-xs font-semibold text-zinc-100"
                >
                  <Save className="w-3.5 h-3.5 text-amber-400" /> Apply &amp; Recompute
                </button>
              </div>

              {statusMsg && (
                <div className="rounded border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
                  {statusMsg}
                </div>
              )}

              {summary && (
                <div className="rounded border border-zinc-800 bg-zinc-950 p-3 text-[11px] text-zinc-400">
                  Report scope: <span className="font-mono text-zinc-200">{summary.total_events}</span> events,{' '}
                  <span className="font-mono text-rose-400">{summary.total_findings}</span> findings,{' '}
                  <span className="font-mono text-amber-400">{summary.total_incidents}</span> incidents.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
