import React, { useCallback, useEffect, useState } from 'react';
import {
  FileSearch,
  FileText,
  Flame,
  ShieldAlert,
  Terminal,
  UploadCloud,
} from 'lucide-react';
import { AnalyzeWorkbenchPage } from './pages/AnalyzeWorkbenchPage';
import { LogExplorerPage } from './pages/LogExplorerPage';
import { ReportsQueryPage } from './pages/ReportsQueryPage';
import { ThreatsChainsPage } from './pages/ThreatsChainsPage';
import { api } from './services/api';
import type {
  AnalyzerSummary,
  CanonicalEvent,
  Finding,
  IncidentDetail,
  IncidentSummary,
  IngestionReport,
  MetricsResponse,
  SamplePreset,
} from './types/tracepoint';

type WorkbenchTab = 'analyze' | 'explorer' | 'threats' | 'reports';

const TABS: { id: WorkbenchTab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'analyze', label: 'Analyze & Ingest', icon: UploadCloud },
  { id: 'explorer', label: 'Log Explorer', icon: FileSearch },
  { id: 'threats', label: 'Threats & Chains', icon: Flame },
  { id: 'reports', label: 'Reports & Query', icon: FileText },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkbenchTab>('analyze');
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [summary, setSummary] = useState<AnalyzerSummary | null>(null);
  const [presets, setPresets] = useState<SamplePreset[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [lastReport, setLastReport] = useState<IngestionReport | null>(null);
  const [topEvents, setTopEvents] = useState<CanonicalEvent[]>([]);

  const refreshAll = useCallback(async () => {
    const [m, sum, fnds, incs, pList, topLogs] = await Promise.all([
      api.getMetrics(),
      api.getAnalyzerSummary(),
      api.getFindings(),
      api.getIncidents(),
      api.getPresets(),
      api.getLogs({ sort_by: 'final_event_risk', limit: '6' }),
    ]);
    setMetrics(m);
    setSummary(sum);
    setFindings(fnds);
    setIncidents(incs);
    setPresets(pList);
    setTopEvents(topLogs.events);
    setRefreshVersion((v) => v + 1);

    if (incs.length > 0) {
      setSelectedIncidentId((prev) =>
        prev && incs.some((i) => i.incident_id === prev) ? prev : incs[0].incident_id
      );
    } else {
      setSelectedIncidentId(null);
      setIncidentDetail(null);
    }
  }, []);

  useEffect(() => {
    refreshAll().catch(() => { });
  }, [refreshAll]);

  useEffect(() => {
    if (!selectedIncidentId) {
      setIncidentDetail(null);
      return;
    }
    api
      .getIncident(selectedIncidentId)
      .then(setIncidentDetail)
      .catch(() => setIncidentDetail(null));
  }, [selectedIncidentId, refreshVersion]);

  return (
    <div className="min-h-screen flex flex-col bg-[#09090b] text-zinc-100">
      {/* Top Threat-Hunter Navigation Bar */}
      <header className="sticky top-0 z-30 border-b border-zinc-800 bg-[#09090b]/95 backdrop-blur">
        <div className="max-w-[1440px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="h-8 w-8 rounded-md bg-amber-500/15 border border-amber-500/40 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-amber-400" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-wider text-zinc-100">THREATLENS</div>
              <div className="text-[10px] font-mono text-zinc-400">SECURITY LOG ANALYZER</div>
            </div>
          </div>

          <nav className="flex items-center gap-1 overflow-x-auto">
            {TABS.map((t) => {
              const Icon = t.icon;
              const active = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition border ${active
                    ? 'border-amber-500/50 bg-amber-500/15 text-amber-300'
                    : 'border-transparent text-zinc-400 hover:text-zinc-100 hover:bg-zinc-900'
                    }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${active ? 'text-amber-400' : 'text-zinc-500'}`} />
                  {t.label}
                </button>
              );
            })}
          </nav>

          <div className="hidden lg:flex items-center gap-2 font-mono text-[11px]">
            {lastReport?.filename && (
              <span className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-zinc-400 max-w-[200px] truncate">
                Source: <span className="text-zinc-100">{lastReport.filename}</span>
              </span>
            )}
            <span className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-zinc-300">
              Events: <span className="text-amber-400 font-semibold">{summary?.total_events ?? 0}</span>
            </span>
            <span className="rounded border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-zinc-300 inline-flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-rose-400" />
              Findings: <span className="text-rose-400 font-semibold">{summary?.total_findings ?? 0}</span>
            </span>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-5">
        {activeTab === 'analyze' && (
          <AnalyzeWorkbenchPage
            presets={presets}
            summary={summary}
            metrics={metrics}
            report={lastReport}
            onReportChange={setLastReport}
            topEvents={topEvents}
            onDataUpdated={refreshAll}
            onNavigateTab={setActiveTab}
          />
        )}
        {activeTab === 'explorer' && (
          <LogExplorerPage metrics={metrics} refreshVersion={refreshVersion} />
        )}
        {activeTab === 'threats' && (
          <ThreatsChainsPage
            summary={summary}
            findings={findings}
            incidents={incidents}
            selectedIncidentId={selectedIncidentId}
            onSelectIncident={setSelectedIncidentId}
            incidentDetail={incidentDetail}
            onDataUpdated={refreshAll}
          />
        )}
        {activeTab === 'reports' && (
          <ReportsQueryPage
            summary={summary}
            incidentDetail={incidentDetail}
            onDataUpdated={refreshAll}
          />
        )}
      </main>
    </div>
  );
}
