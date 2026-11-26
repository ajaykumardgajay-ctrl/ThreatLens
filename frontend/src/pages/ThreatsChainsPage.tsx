import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  Cpu,
  GitBranch,
  Globe,
  Pause,
  Play,
  RotateCcw,
  ShieldAlert,
  SkipBack,
  SkipForward,
  Terminal,
  User,
} from 'lucide-react';
import { AttackGraphCanvas } from '../components/AttackGraphCanvas';
import { MlBreakdownPanel, RiskBadges } from '../components/MlBreakdownPanel';
import { ScoreBreakdownPanel } from '../components/ScoreBreakdownPanel';
import { api } from '../services/api';
import type {
  AnalyzerSummary,
  Finding,
  IncidentDetail,
  IncidentSummary,
} from '../types/tracepoint';
import { formatBytes, formatShortTime, formatUtcTime, severityBadgeClass } from '../utils/format';

interface ThreatsChainsPageProps {
  summary: AnalyzerSummary | null;
  findings: Finding[];
  incidents: IncidentSummary[];
  selectedIncidentId: string | null;
  onSelectIncident: (id: string) => void;
  incidentDetail: IncidentDetail | null;
  onDataUpdated: () => Promise<void>;
}

export const ThreatsChainsPage: React.FC<ThreatsChainsPageProps> = ({
  summary,
  findings,
  incidents,
  selectedIncidentId,
  onSelectIncident,
  incidentDetail,
  onDataUpdated,
}) => {
  const [chainMode, setChainMode] = useState<'replay' | 'graph'>('replay');
  const [stepIdx, setStepIdx] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [mlThreshold, setMlThreshold] = useState<number>(60);
  const [updatingThreshold, setUpdatingThreshold] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then((s) => {
        if (typeof s.ml_anomaly_threshold === 'number') {
          setMlThreshold(s.ml_anomaly_threshold);
        }
      })
      .catch(() => {});
  }, []);

  const applyMlThreshold = async (val: number) => {
    setUpdatingThreshold(true);
    try {
      await api.updateSettings({ ml_anomaly_threshold: val });
      await onDataUpdated();
    } finally {
      setUpdatingThreshold(false);
    }
  };

  const sortedFindings = useMemo(
    () =>
      [...findings].sort(
        (a, b) =>
          (b.final_event_risk ?? 0) - (a.final_event_risk ?? 0) ||
          a.timestamp.localeCompare(b.timestamp)
      ),
    [findings]
  );

  const timeline = incidentDetail?.timeline ?? [];

  useEffect(() => {
    setStepIdx(0);
    setPlaying(false);
  }, [incidentDetail?.incident_id]);

  useEffect(() => {
    if (!playing || timeline.length <= 1) return;
    const timer = window.setInterval(() => {
      setStepIdx((prev) => {
        if (prev >= timeline.length - 1) {
          setPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 2100);
    return () => window.clearInterval(timer);
  }, [playing, timeline.length]);

  const activeStep = timeline[stepIdx] ?? null;
  const { highlightNodes, highlightEdges } = useMemo(() => {
    const nSet = new Set<string>();
    const eSet = new Set<string>();
    for (let i = 0; i <= stepIdx && i < timeline.length; i++) {
      timeline[i].highlight_node_ids.forEach((id) => nSet.add(id));
      timeline[i].highlight_edge_ids.forEach((id) => eSet.add(id));
    }
    return { highlightNodes: Array.from(nSet), highlightEdges: Array.from(eSet) };
  }, [timeline, stepIdx]);

  if (!summary || summary.total_events === 0) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-[#111114] p-10 text-center text-xs text-zinc-400">
        No logs analyzed yet. Upload logs or load a preset in <span className="text-amber-400">Analyze &amp; Ingest</span>.
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Live ML Anomaly Threshold Slider Bar */}
      <div className="rounded-lg border border-zinc-800 bg-[#111114] px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="text-xs font-semibold text-zinc-100 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-amber-400" />
            Explainable IsolationForest ML Layer
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/15 border border-amber-500/40 text-amber-300">
              Threshold: {mlThreshold}
            </span>
            {updatingThreshold && (
              <span className="font-mono text-[10px] text-zinc-400">Recomputing...</span>
            )}
          </div>
          <p className="text-[11px] text-zinc-400 mt-0.5">
            Adjust the ML Anomaly Threshold live to surface or suppress standalone behavioral anomalies and hybrid risk boosts.
          </p>
        </div>

        <div className="flex items-center gap-3 min-w-[260px]">
          <span className="font-mono text-[10px] text-zinc-500">35</span>
          <input
            type="range"
            min={35}
            max={95}
            step={5}
            value={mlThreshold}
            onChange={(e) => setMlThreshold(Number(e.target.value))}
            onMouseUp={() => applyMlThreshold(mlThreshold)}
            onTouchEnd={() => applyMlThreshold(mlThreshold)}
            className="flex-1 accent-amber-500 cursor-pointer"
          />
          <span className="font-mono text-[10px] text-zinc-500">95</span>
          <button
            type="button"
            onClick={() => applyMlThreshold(mlThreshold)}
            disabled={updatingThreshold}
            className="rounded border border-zinc-700 bg-zinc-950 hover:border-amber-500/60 px-2.5 py-1 text-[11px] font-medium text-amber-300 disabled:opacity-50"
          >
            Apply
          </button>
        </div>
      </div>

      {/* Extracted IOCs + Top Attacking IPs & Accounts */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-5 rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            Extracted Indicators of Compromise ({summary.iocs.length})
          </h3>
          {summary.iocs.length === 0 ? (
            <p className="text-xs text-zinc-500">No high-confidence IOCs extracted.</p>
          ) : (
            <div className="max-h-56 overflow-y-auto space-y-1.5">
              {summary.iocs.map((ioc, i) => (
                <div
                  key={`${ioc.type}-${ioc.value}-${i}`}
                  className="flex items-center justify-between gap-2 rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 text-xs"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] uppercase text-zinc-500">{ioc.type}</span>
                      <span className="font-mono font-semibold text-amber-300 truncate">{ioc.value}</span>
                    </div>
                    <div className="text-[10px] text-zinc-400 truncate">{ioc.context}</div>
                  </div>
                  <span
                    className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold uppercase shrink-0 ${severityBadgeClass(
                      ioc.severity
                    )}`}
                  >
                    {ioc.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="xl:col-span-4 rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-amber-400" />
            Top Source IPs
          </h3>
          <div className="max-h-56 overflow-y-auto space-y-1">
            {summary.top_ips.slice(0, 8).map((ip) => (
              <div
                key={ip.ip}
                className="flex items-center justify-between rounded border border-zinc-800/80 bg-zinc-950 px-2.5 py-1.5 font-mono text-[11px]"
              >
                <div className="min-w-0">
                  <span className={ip.is_flagged ? 'text-rose-400 font-semibold' : 'text-zinc-200'}>
                    {ip.ip}
                  </span>
                  {ip.geos[0] && <span className="text-zinc-500 ml-1.5">({ip.geos[0]})</span>}
                </div>
                <span className="text-zinc-400 shrink-0">
                  {ip.total} ev · <span className="text-rose-400">{ip.failures} fail</span>
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="xl:col-span-3 rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2.5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
            <User className="w-3.5 h-3.5 text-amber-400" />
            Top Accounts
          </h3>
          <div className="max-h-56 overflow-y-auto space-y-1">
            {summary.top_users.slice(0, 8).map((u) => (
              <div
                key={u.user}
                className="flex items-center justify-between rounded border border-zinc-800/80 bg-zinc-950 px-2.5 py-1.5 font-mono text-[11px]"
              >
                <span className={u.is_flagged ? 'text-amber-300 font-semibold' : 'text-zinc-200'}>
                  {u.user}
                </span>
                <span className="text-zinc-400">
                  {u.total} ev · {u.unique_ips} IP
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Correlated Attack Chains + Interactive Replay & Graph */}
      {incidents.length > 0 && incidentDetail && (
        <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-4">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-zinc-800 pb-3">
            <div className="flex flex-wrap items-center gap-2.5">
              <GitBranch className="w-4 h-4 text-amber-400" />
              <select
                value={selectedIncidentId || ''}
                onChange={(e) => onSelectIncident(e.target.value)}
                className="rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1 font-mono text-xs text-amber-300"
              >
                {incidents.map((inc) => (
                  <option key={inc.incident_id} value={inc.incident_id}>
                    {inc.incident_id} — {inc.title} ({inc.risk_score}/100)
                  </option>
                ))}
              </select>
              <span
                className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${severityBadgeClass(
                  incidentDetail.severity
                )}`}
              >
                {incidentDetail.severity} &middot; {incidentDetail.risk_score}/100
              </span>
              <RiskBadges
                ruleScore={incidentDetail.rule_score ?? incidentDetail.risk_score}
                mlScore={incidentDetail.ml_anomaly_score ?? 0}
                combinedRisk={incidentDetail.combined_risk_score ?? incidentDetail.risk_score}
              />
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setChainMode('replay')}
                className={`px-3 py-1 rounded text-xs font-medium border transition ${
                  chainMode === 'replay'
                    ? 'border-amber-500/60 bg-amber-500/15 text-amber-300'
                    : 'border-zinc-800 bg-zinc-950 text-zinc-400'
                }`}
              >
                Attack Replay
              </button>
              <button
                onClick={() => setChainMode('graph')}
                className={`px-3 py-1 rounded text-xs font-medium border transition ${
                  chainMode === 'graph'
                    ? 'border-amber-500/60 bg-amber-500/15 text-amber-300'
                    : 'border-zinc-800 bg-zinc-950 text-zinc-400'
                }`}
              >
                Full Graph &amp; Score
              </button>
            </div>
          </div>

          {chainMode === 'replay' && timeline.length > 0 ? (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx(0);
                    }}
                    className="rounded border border-zinc-700 bg-zinc-950 p-1.5 text-zinc-300 hover:border-zinc-500"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx((i) => Math.max(0, i - 1));
                    }}
                    disabled={stepIdx === 0}
                    className="rounded border border-zinc-700 bg-zinc-950 disabled:opacity-40 px-2.5 py-1 text-xs text-zinc-200 inline-flex items-center gap-1"
                  >
                    <SkipBack className="w-3.5 h-3.5" /> Prev
                  </button>
                  <button
                    onClick={() => {
                      if (stepIdx >= timeline.length - 1) setStepIdx(0);
                      setPlaying((p) => !p);
                    }}
                    className="rounded bg-amber-500 hover:bg-amber-400 px-3 py-1 text-xs font-semibold text-zinc-950 inline-flex items-center gap-1.5"
                  >
                    {playing ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    {playing ? 'Pause' : 'Play Attack Replay'}
                  </button>
                  <button
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx((i) => Math.min(timeline.length - 1, i + 1));
                    }}
                    disabled={stepIdx >= timeline.length - 1}
                    className="rounded border border-zinc-700 bg-zinc-950 disabled:opacity-40 px-2.5 py-1 text-xs text-zinc-200 inline-flex items-center gap-1"
                  >
                    Next <SkipForward className="w-3.5 h-3.5" />
                  </button>
                </div>
                <span className="font-mono text-xs text-zinc-400">
                  Step <span className="text-amber-400 font-bold">{stepIdx + 1}</span> / {timeline.length}
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
                {timeline.map((step, idx) => (
                  <button
                    key={step.event_id}
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx(idx);
                    }}
                    className={`text-left rounded border px-2.5 py-1.5 transition ${
                      idx === stepIdx
                        ? 'border-amber-400 bg-amber-500/15'
                        : idx < stepIdx
                        ? 'border-rose-500/40 bg-rose-500/5'
                        : 'border-zinc-800 bg-zinc-950 opacity-70'
                    }`}
                  >
                    <div className="font-mono text-[10px] text-zinc-400">
                      #{step.step_index} · {formatShortTime(step.timestamp)}Z
                    </div>
                    <div className="text-[11px] font-medium text-zinc-100 truncate">{step.stage}</div>
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
                {activeStep && (
                  <div className="xl:col-span-5 rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                      <div>
                        <div className="text-[10px] uppercase tracking-wider text-amber-400 font-semibold">
                          Stage {activeStep.step_index}
                        </div>
                        <div className="text-sm font-bold text-zinc-100">{activeStep.stage}</div>
                      </div>
                      <span className="font-mono text-[11px] text-zinc-400">
                        {formatUtcTime(activeStep.timestamp)}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                      <div className="rounded border border-zinc-800 bg-[#111114] p-2">
                        <div className="text-[10px] text-zinc-500 font-sans">Identity / Pivot</div>
                        <div className="text-amber-300 flex items-center gap-1 mt-0.5">
                          {activeStep.user}
                          {activeStep.target_user && (
                            <>
                              <ArrowRight className="w-3 h-3 text-rose-400" />
                              <span className="text-rose-400">{activeStep.target_user}</span>
                            </>
                          )}
                        </div>
                      </div>
                      <div className="rounded border border-zinc-800 bg-[#111114] p-2">
                        <div className="text-[10px] text-zinc-500 font-sans">Host &amp; IP</div>
                        <div className="text-zinc-200 truncate mt-0.5">
                          {activeStep.hostname} · {activeStep.src_ip || activeStep.dest_ip || 'local'}
                        </div>
                      </div>
                    </div>

                    <div className="rounded border border-zinc-800 bg-[#111114] p-2.5 text-xs">
                      <div className="text-[10px] uppercase text-zinc-500 mb-0.5">Correlation Link</div>
                      <div className="text-amber-300">{activeStep.relationship_to_previous}</div>
                    </div>

                    <p className="text-xs text-zinc-200 leading-relaxed">
                      {activeStep.explanation}
                      {activeStep.bytes_out > 0 ? ` (${formatBytes(activeStep.bytes_out)})` : ''}
                    </p>

                    <RiskBadges
                      ruleScore={activeStep.rule_score ?? 0}
                      mlScore={activeStep.ml_anomaly_score ?? 0}
                      combinedRisk={activeStep.final_event_risk ?? 0}
                    />

                    <MlBreakdownPanel
                      mlScore={activeStep.ml_anomaly_score ?? 0}
                      reasons={activeStep.ml_reasons}
                      deviations={activeStep.ml_feature_deviations}
                    />

                    <div>
                      <div className="flex items-center justify-between text-[10px] text-zinc-500 uppercase mb-1">
                        <span className="inline-flex items-center gap-1">
                          <Terminal className="w-3 h-3 text-amber-400" /> Raw Evidence
                        </span>
                        <span className="font-mono text-amber-300">{activeStep.event_id}</span>
                      </div>
                      <pre className="rounded border border-zinc-800 bg-black p-2.5 font-mono text-[10px] text-zinc-200 whitespace-pre-wrap break-all">
                        {activeStep.raw_log}
                      </pre>
                    </div>
                  </div>
                )}

                <div className="xl:col-span-7">
                  <AttackGraphCanvas
                    graph={incidentDetail.graph}
                    highlightNodeIds={highlightNodes}
                    highlightEdgeIds={highlightEdges}
                    dimUnfocused={true}
                    heightClass="h-[460px]"
                  />
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <AttackGraphCanvas graph={incidentDetail.graph} heightClass="h-[460px]" />
              <ScoreBreakdownPanel breakdown={incidentDetail.score_breakdown} />
            </div>
          )}
        </div>
      )}

      {/* All Detection Findings (Ranked by Combined Risk) */}
      <div className="space-y-2.5">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
          Detection Findings Ranked by Combined Risk ({sortedFindings.length})
        </h3>
        {sortedFindings.map((f) => (
          <div key={f.finding_id} className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs font-bold text-amber-400">{f.finding_id}</span>
                <span
                  className={`px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${severityBadgeClass(
                    f.severity
                  )}`}
                >
                  {f.severity}
                </span>
                <span className="px-2 py-0.5 rounded border border-zinc-700 bg-zinc-900 font-mono text-[10px] text-zinc-300 inline-flex items-center gap-1">
                  {f.detection_source === 'ml' && <Cpu className="w-3 h-3 text-amber-400" />}
                  {f.detection_source === 'ml' ? 'BEHAVIORAL ANOMALY (ML)' : 'RULE'}
                </span>
                <span className="text-xs font-semibold text-zinc-100">{f.detector_name}</span>
              </div>
              <span className="font-mono text-[11px] text-zinc-400">
                {formatUtcTime(f.timestamp)} &middot; conf {Math.round(f.confidence * 100)}%
              </span>
            </div>

            <RiskBadges
              ruleScore={f.rule_score ?? 0}
              mlScore={f.anomaly_score != null ? f.anomaly_score * 100 : 0}
              combinedRisk={f.final_event_risk ?? 0}
            />

            <p className="text-xs text-zinc-300">{f.description}</p>
            <div className="font-mono text-[11px] text-amber-300/90">
              Condition: {f.triggered_condition}
            </div>

            <MlBreakdownPanel
              mlScore={f.anomaly_score != null ? f.anomaly_score * 100 : 0}
              reasons={f.ml_reasons}
              deviations={f.feature_contributions}
            />
          </div>
        ))}
      </div>
    </div>
  );
};
