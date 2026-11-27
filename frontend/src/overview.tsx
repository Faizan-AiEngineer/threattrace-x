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
  const tick = Math.max(1, Math.ceil(max / 4));
  const ceiling = tick * 4;
  const width = 540 / trend.length;
  const labelDates = trend.length <= 7 ? 1 : 2;
  return (
    <div className="trend-panel">
      <svg
        className="trend-chart"
        viewBox="0 0 620 190"
        role="img"
        aria-label="Event volume by recorded UTC date"
      >
        {[0, 1, 2, 3, 4].map((index) => (
          <g key={index}>
            <line
              x1="48"
              x2="588"
              y1={22 + index * 32}
              y2={22 + index * 32}
              stroke="#2b3a4e"
              strokeDasharray="4 5"
            />
            <text x="36" y={26 + index * 32} textAnchor="end">
              {tick * (4 - index)}
            </text>
          </g>
        ))}
        {trend.map(([day, value], index) => {
          const center = 48 + width * (index + 0.5);
          const barWidth = Math.min(52, width * 0.7);
          const height = (value * 128) / ceiling;
          return (
            <g key={day}>
              <rect
                className="trend-bar"
                x={center - barWidth / 2}
                y={150 - height}
                width={barWidth}
                height={height}
                rx="3"
              >
                <title>
                  {day} UTC · {value} events
                </title>
              </rect>
              {index % labelDates === 0 && (
                <text x={center} y="175" textAnchor="middle">
                  {day.slice(5)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <details className="trend-data">
        <summary>Daily counts</summary>
        <ul>
          {trend.map(([day, value]) => (
            <li key={day}>
              <time dateTime={day}>{day}</time>
              <strong>{value.toLocaleString()}</strong>
            </li>
          ))}
        </ul>
      </details>
    </div>
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
                <section key={title} className={"stat-card stat-" + color}>
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
                hint="Most recent recorded UTC dates · dates without events are omitted"
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
