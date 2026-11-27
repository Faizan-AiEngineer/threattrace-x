export type User = {
  id: string;
  username: string;
  role: "administrator" | "investigator";
  created_at: string;
  disabled_at: string | null;
  password_change_required: boolean;
};
export type Case = {
  id: string;
  title: string;
  description: string;
  investigator: string;
  classification: string;
  status: string;
  severity: string;
  synthetic: boolean;
  created_at: string;
  updated_at: string;
  owner_id: string;
};
export type Page<T> = {
  items: T[];
  page: number;
  limit: number;
  total: number;
};
export type Evidence = {
  id: string;
  filename: string;
  size: number;
  format: string;
  source: string;
  sha256: string;
  integrity: string;
  state: string;
  imported_at: string;
  collection_at: string | null;
  custodian: string;
  parser_version: string;
  clock_offset: number;
  timezone_offset: number;
  stats: {
    parsed: number;
    malformed: number;
    uncertain?: number;
    errors: { source_ref: string; reason: string }[];
  };
  verifications?: {
    id: string;
    status: string;
    timestamp: string;
    actor: string;
    actual_hash: string | null;
  }[];
};
export type Event = {
  id: string;
  timestamp: string | null;
  original_timestamp: string | null;
  time_quality: string;
  source_type: string;
  source_ref: string;
  evidence_id: string;
  action: string;
  severity: string;
  category: string;
  hostname: string | null;
  username: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  clock_offset: number;
  metadata: unknown;
  relationships?: Edge[];
  notes?: Note[];
  findings?: { id: string; name: string }[];
};
export type Edge = {
  id: string;
  source_id: string;
  target_id: string;
  kind: string;
  confidence: number;
  version: string;
  explanation: string;
  review: string;
  reason: string;
  attributes: { kind: string; value: string; seconds_apart: number }[];
};
export type Finding = {
  id: string;
  name: string;
  severity: string;
  stage: string;
  rule_id: string;
  explanation: string;
  limitations: string;
  steps: string;
  technique: string | null;
  version: string;
  confidence: {
    score: number | null;
    category: string;
    components: Record<
      string,
      { weight: number; value: number | null; contribution: number | null }
    >;
  };
  evidence_ids: string[];
  event_ids: string[];
  timestamp: string | null;
  override: number | null;
  review_reason: string;
};
export type Note = {
  id: string;
  actor: string;
  timestamp: string;
  body: string;
  event_id: string | null;
};
export type Activity = {
  id: string;
  case_id: string | null;
  actor: string;
  action: string;
  timestamp: string;
  detail: string;
};
export type Rule = {
  id: string;
  name: string;
  severity: string;
  technique: string | null;
  version: string;
  enabled: boolean;
  threshold: number;
  window: number;
};
export type Indicator = {
  id: string;
  value: string;
  kind: string;
  source: string;
  confidence: number;
  description: string;
  expires_at: string | null;
  tags: string[];
  match_count: number;
  event_ids: string[];
};
export type Custody = Page<{
  id: string;
  sequence: number;
  actor: string;
  action: string;
  timestamp: string;
  reason: string;
  previous_hash: string | null;
  record_hash: string;
}> & {
  verification: {
    valid: boolean;
    records: number;
    reason: string | null;
    failed_at: number | null;
  };
};
export type Dashboard = {
  active_cases: number;
  evidence: number;
  verified: number;
  integrity_failures: number;
  critical: number;
  unresolved: number;
  events: number;
  matches: number;
  evidence_status: Record<string, number>;
  severity: Record<string, number>;
  trend: [string, number][];
  active: Case[];
  recent_activity: (Activity & { case_id: string; case_title: string })[];
  recent_findings: (Finding & { case_id: string; case_title: string })[];
};

export const apiRoot = "/api/v1";
export class ApiError extends Error {
  status: number;
  constructor(status: number, text: string) {
    super(text);
    this.status = status;
  }
}
export async function request(path: string, method = "GET", body?: unknown) {
  const isForm = body instanceof FormData;
  const response = await fetch(apiRoot + path, {
    method,
    credentials: "same-origin",
    headers: {
      "X-TTX-Request": "1",
      ...(body && !isForm ? { "Content-Type": "application/json" } : {}),
    },
    body: isForm ? body : body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    const result = await response.json().catch(() => ({}));
    const detail = Array.isArray(result.detail)
      ? result.detail
          .map(
            (problem: { loc: string[]; msg: string }) =>
              problem.loc.slice(1).join(" ") + " " + problem.msg,
          )
          .join(" · ")
      : result.detail;
    if (response.status === 401 && !path.startsWith("/auth/"))
      window.dispatchEvent(new Event("ttx-session-expired"));
    throw new ApiError(
      response.status,
      detail || "Request failed (" + response.status + ")",
    );
  }
  return response;
}
export async function api<T>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const response = await request(path, method, body);
  return response.status === 204 ? (undefined as T) : await response.json();
}
export async function download(
  path: string,
  filename: string,
  method = "POST",
) {
  const response = await request(path, method);
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}
export function query(values: Record<string, string | number | undefined>) {
  const result = new URLSearchParams();
  for (const [key, value] of Object.entries(values)) {
    if (value !== undefined && value !== "") result.set(key, String(value));
  }
  return "?" + result.toString();
}
