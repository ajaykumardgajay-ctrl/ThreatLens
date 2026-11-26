import type {
  AnalyzerSummary,
  CanonicalEvent,
  Finding,
  IncidentDetail,
  IncidentSummary,
  IngestionReport,
  InvestigationResponse,
  MetricsResponse,
  RuntimeSettings,
  SamplePreset,
} from '../types/tracepoint';

const API_BASE = import.meta.env.VITE_API_BASE || '';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, init);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      // ignore json parse failure
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  getMetrics: () => request<MetricsResponse>('/api/metrics'),
  getIncidents: () => request<IncidentSummary[]>('/api/incidents'),
  getIncident: (id: string) => request<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
  getFindings: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<Finding[]>(`/api/findings${qs}`);
  },
  getLogs: (params?: Record<string, string>) => {
    const qs = params ? '?' + new URLSearchParams(params).toString() : '';
    return request<{ total: number; limit: number; offset: number; events: CanonicalEvent[] }>(
      `/api/logs${qs}`
    );
  },
  loadDemo: () => request<IngestionReport>('/api/demo/load', { method: 'POST' }),
  resetDemo: () => request<{ status: string; message: string }>('/api/demo/reset', { method: 'POST' }),
  uploadLogs: (file: File, logFormat = 'auto', replaceExisting = true) => {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('log_format', logFormat);
    fd.append('replace_existing', String(replaceExisting));
    return request<IngestionReport>('/api/logs/upload', { method: 'POST', body: fd });
  },
  analyzeRawLogs: (rawText: string, logFormat = 'auto', replaceExisting = true) =>
    request<IngestionReport>('/api/logs/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        raw_text: rawText,
        log_format: logFormat,
        replace_existing: replaceExisting,
      }),
    }),
  investigate: (incidentId: string, question: string) =>
    request<InvestigationResponse>('/api/investigate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ incident_id: incidentId, question }),
    }),
  getSettings: () => request<RuntimeSettings>('/api/settings'),
  updateSettings: (payload: Partial<RuntimeSettings>) =>
    request<{ status: string; settings: RuntimeSettings }>('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  retrainMl: () =>
    request<{ status: string; training: Record<string, unknown> }>('/api/ml/retrain', {
      method: 'POST',
    }),
  getAnalyzerSummary: () => request<AnalyzerSummary>('/api/analyzer/summary'),
  getPresets: () => request<SamplePreset[]>('/api/analyzer/presets'),
  loadPreset: (presetId: string) =>
    request<IngestionReport>(`/api/analyzer/presets/${encodeURIComponent(presetId)}`, {
      method: 'POST',
    }),
  exportUrl: (format: 'pdf' | 'json' | 'csv') =>
    `${API_BASE}/api/analyzer/export?format=${format}`,
};
