import {
  Activity as ActivityIcon,
  ArrowRight,
  Briefcase,
  CircleAlert,
  Database,
  FileSearch,
  Fingerprint,
  Layers3,
  ShieldCheck,
} from "lucide-react";
import type { Dashboard } from "./api";
import { Badge, Empty, label, Load, Panel, useData } from "./ui";

const severityColors: Record<string, string> = {
  critical: "#fb6c78",
  high: "#eb9c5d",
  medium: "#f1c770",
  low: "#6fa6ed",
  info: "#7b91aa",
};

function Trend({ trend }: { trend: [string, number][] }) {
  if (!trend.length)
    return <Empty>Import timestamped evidence to see event volume.</Empty>;
  const max = Math.max(...trend.map(([, value]) => value), 1);
  const step = 540 / Math.max(trend.length - 1, 1);
  const points = trend.map(([, value], index) => [
    48 + index * step,
    153 - (value * 120) / max,
  ]);
  const line = points.map((point) => point.join(",")).join(" ");
  return (
    <svg
      className="trend-chart"
      viewBox="0 0 620 190"
      role="img"
      aria-label="Daily event volume in UTC"
    >
      <defs>
        <linearGradient id="trend-fill" x2="0%" y2="100%">
          <stop stopColor="#34c9df" stopOpacity=".24" />
          <stop offset="100%" stopColor="#34c9df" stopOpacity="0" />
        </linearGradient>
      </defs>
      {[0, 1, 2, 3].map((index) => (
        <g key={index}>
          <line
            x1="48"
            x2="588"
            y1={33 + index * 40}
            y2={33 + index * 40}
            stroke="#263345"
            strokeDasharray="4 5"
          />
          <text x="36" y={37 + index * 40} textAnchor="end">
            {Math.round((max * (3 - index)) / 3)}
          </text>
        </g>
      ))}
      {trend.length > 1 && (
        <polygon fill="url(#trend-fill)" points={line + " 588,153 48,153"} />
      )}
      <polyline
        fill="none"
        stroke="#55d8eb"
        strokeWidth="2.5"
        strokeLinejoin="round"
        points={line}
      />
      {points.map(([x, y], index) => (
        <g key={index}>
          <circle
            cx={x}
            cy={y}
            r="4.5"
            fill="#142534"
            stroke="#6de0ec"
            strokeWidth="2"
          >
            <title>
              {trend[index][0]} UTC · {trend[index][1]} events
            </title>
          </circle>
          {(trend.length < 8 || index % 2 === 0) && (
            <text x={x} y="177" textAnchor="middle">
              {trend[index][0].slice(5)}
            </text>
          )}
        </g>
      ))}
    </svg>
  );
}
function Severity({ values }: { values: Record<string, number> }) {
  const keys = Object.keys(severityColors);
  const total = Object.values(values).reduce((sum, value) => sum + value, 0);
  let position = 0;
  const gradient = keys
    .filter((key) => values[key])
    .map((key) => {
      const start = position;
      position += (values[key] / total) * 100;
      return severityColors[key] + " " + start + "% " + position + "%";
    })
    .join(", ");
  return (
    <div className="severity-body">
      <div
        className="donut"
        style={{
          background: total ? "conic-gradient(" + gradient + ")" : "#293648",
        }}
      >
        <div>
          <strong>{total}</strong>
          <small>Findings</small>
        </div>
      </div>
      <div className="legend">
        {keys.map((key) => (
          <div key={key}>
            <i style={{ background: severityColors[key] }} />
            {label(key)}
            <strong>{values[key] || 0}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}
function when(value: string) {
  const minutes = Math.max(
    0,
    Math.floor((Date.now() - new Date(value).getTime()) / 60000),
  );
  return minutes < 1
    ? "Just now"
    : minutes < 60
      ? minutes + "m ago"
      : minutes < 1440
        ? Math.floor(minutes / 60) + "h ago"
        : Math.floor(minutes / 1440) + "d ago";
}
export function Overview({ username }: { username: string }) {
  const state = useData<Dashboard>("/dashboard");
  return (
    <Load state={state}>
      {(data) => {
        const stats = [
          [
            "Active investigations",
            data.active_cases,
            "Cases requiring review",
            Briefcase,
            "cyan",
          ],
          [
            "Evidence items",
            data.evidence,
            data.verified +
              " verified · " +
              data.integrity_failures +
              " integrity failures",
            Database,
            "green",
          ],
          [
            "Open findings",
            data.unresolved,
            data.critical + " critical findings",
            CircleAlert,
            "amber",
          ],
          [
            "Processed events",
            data.events,
            data.matches + " indicator matches",
            ActivityIcon,
            "purple",
          ],
        ] as const;
        return (
          <>
            <div className="page-heading">
              <div>
                <span className="eyebrow">
                  <Layers3 size={14} /> INVESTIGATION WORKSPACE
                </span>
                <h1>Investigation overview</h1>
                <p>
                  Evidence integrity, case activity and forensic findings across
                  your investigations.
                </p>
              </div>
              <a className="button primary" href="#/cases/new">
                <Briefcase size={17} /> New investigation
              </a>
            </div>
            {data.active.some((item) => item.synthetic) && (
              <div className="demo-banner">
                <Fingerprint size={16} />
                <span>
                  <strong>Synthetic demonstration</strong> · Orchid Research
                  records are fictional.
                </span>
              </div>
            )}
            <div className="stats-grid">
              {stats.map(([title, value, detail, Icon, color]) => (
                <section key={title} className="stat-card">
                  <div className="stat-title">
                    {title}
                    <span className={"stat-icon " + color}>
                      <Icon size={17} />
                    </span>
                  </div>
                  <strong>{value.toLocaleString()}</strong>
                  <small>{detail}</small>
                </section>
              ))}
            </div>
            <div className="chart-grid">
              <Panel
                title="Event volume"
                hint="Normalized forensic events by UTC date"
                action={<span className="section-chip">Latest 14 dates</span>}
              >
                <Trend trend={data.trend} />
              </Panel>
              <Panel
                title="Finding severity"
                hint="Current findings across accessible cases"
              >
                <Severity values={data.severity} />
              </Panel>
            </div>
            <div className="chart-grid equal">
              <Panel
                title="Active investigations"
                hint="Cases requiring investigator attention"
                action={
                  <a className="inline-link" href="#/cases">
                    View cases <ArrowRight size={14} />
                  </a>
                }
              >
                {data.active.length ? (
                  <div className="dense-list">
                    {data.active.map((item) => (
                      <a
                        className="dense-row"
                        key={item.id}
                        href={"#/cases/" + item.id}
                      >
                        <span className="row-icon">
                          <Briefcase size={16} />
                        </span>
                        <span>
                          <strong>{item.title}</strong>
                          <small>{item.classification}</small>
                        </span>
                        <Badge value={item.severity} />
                      </a>
                    ))}
                  </div>
                ) : (
                  <Empty>Create a case to start an investigation.</Empty>
                )}
              </Panel>
              <Panel
                title="Recent activity"
                hint={"Audited activity visible to " + username}
              >
                {data.recent_activity.length ? (
                  <div className="dense-list">
                    {data.recent_activity.slice(0, 5).map((item) => (
                      <a
                        className="dense-row"
                        key={item.id}
                        href={"#/cases/" + item.case_id}
                      >
                        <span className="row-icon">
                          <ActivityIcon size={15} />
                        </span>
                        <span>
                          <strong>{label(item.action)}</strong>
                          <small>
                            {item.case_title} · {item.actor}
                          </small>
                        </span>
                        <small>{when(item.timestamp)}</small>
                      </a>
                    ))}
                  </div>
                ) : (
                  <Empty>No case activity yet.</Empty>
                )}
              </Panel>
            </div>
            <div className="chart-grid equal">
              <Panel
                title="Evidence integrity"
                hint="Last recorded SHA-256 check"
              >
                <div className="overview-inline">
                  <div>
                    <ShieldCheck size={19} />
                    <strong>{data.verified}</strong>
                    <small>Verified</small>
                  </div>
                  <div>
                    <FileSearch size={19} />
                    <strong>{data.evidence_status.unverified || 0}</strong>
                    <small>Awaiting verification</small>
                  </div>
                  <div>
                    <CircleAlert size={19} />
                    <strong>{data.integrity_failures}</strong>
                    <small>Failed</small>
                  </div>
                </div>
              </Panel>
              <Panel
                title="Recent findings"
                hint="Linked evidence and review status"
              >
                {data.recent_findings.length ? (
                  <div className="dense-list">
                    {data.recent_findings.map((item) => (
                      <a
                        className="dense-row"
                        key={item.id}
                        href={
                          "#/cases/" + item.case_id + "/findings/" + item.id
                        }
                      >
                        <span className="row-icon">
                          <CircleAlert size={16} />
                        </span>
                        <span>
                          <strong>{item.name}</strong>
                          <small>{item.case_title}</small>
                        </span>
                        <Badge value={item.severity} />
                      </a>
                    ))}
                  </div>
                ) : (
                  <Empty>
                    Run analysis on an investigation to see findings.
                  </Empty>
                )}
              </Panel>
            </div>
          </>
        );
      }}
    </Load>
  );
}
