import { useState } from "react";
import { Download, FlaskConical, Save, ShieldCheck } from "lucide-react";
import { api, download } from "./api";
import type { Rule, User } from "./api";
import { AdminSettings, PasswordChange } from "./access";
import {
  Badge,
  date,
  definition,
  Empty,
  Feedback,
  formData,
  label,
  Load,
  Modal,
  Panel,
  Table,
  useAction,
  useData,
} from "./ui";

function RuleRow({ rule, editable }: { rule: Rule; editable: boolean }) {
  const [enabled, setEnabled] = useState(rule.enabled);
  const action = useAction();
  const auth = rule.id.startsWith("auth_");
  const transfer = rule.id === "transfer";
  return (
    <form
      className="rule-row"
      onSubmit={(event) => {
        const data = formData(event);
        void action.run(async () => {
          await api("/rules/" + rule.id, "PUT", {
            enabled,
            threshold: Number(data.get("threshold") ?? rule.threshold),
            window: Number(data.get("window") ?? rule.window),
          });
        }, "Rule saved.");
      }}
    >
      <div>
        <strong>{rule.name}</strong>
        <small>
          {rule.id} · v{rule.version}
          {rule.technique ? " · " + rule.technique : ""}
        </small>
      </div>
      <Badge value={rule.severity} />
      <label className="checkbox">
        <input
          type="checkbox"
          checked={enabled}
          disabled={!editable}
          onChange={(event) => setEnabled(event.target.checked)}
        />{" "}
        Enabled
      </label>
      {auth || transfer ? (
        <label className="filter">
          <span>{transfer ? "Byte threshold" : "Failure threshold"}</span>
          <input
            name="threshold"
            type="number"
            min={1}
            max={auth ? 1000 : 2147483647}
            defaultValue={rule.threshold}
            disabled={!editable}
            required
          />
        </label>
      ) : (
        <span />
      )}
      {auth ? (
        <label className="filter">
          <span>Window (s)</span>
          <input
            name="window"
            type="number"
            min={1}
            max={86400}
            defaultValue={rule.window}
            disabled={!editable}
            required
          />
        </label>
      ) : (
        <span />
      )}
      {editable && (
        <button title={"Save " + rule.name} disabled={action.busy}>
          <Save size={15} /> Save
        </button>
      )}
      <Feedback message={action.message} error={action.error} />
    </form>
  );
}
export function RuleSettings({ user }: { user: User }) {
  const state = useData<Rule[]>("/rules");
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Detection rules</h1>
          <p>
            Configure defensive rule activation, thresholds and evaluation
            windows.
          </p>
        </div>
      </div>
      <Panel
        title="Rule catalog"
        hint="Changes apply when case analysis next runs"
      >
        <Load state={state}>
          {(rules) => (
            <div className="rule-list">
              {rules.map((rule) => (
                <RuleRow
                  key={rule.id}
                  rule={rule}
                  editable={user.role === "administrator"}
                />
              ))}
            </div>
          )}
        </Load>
      </Panel>
    </>
  );
}
export function SettingsView({ user }: { user: User }) {
  const [changing, setChanging] = useState(false);
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Settings</h1>
          <p>Local account and investigation access management.</p>
        </div>
      </div>
      <Panel title="Current session" action={<ShieldCheck size={20} />}>
        <div className="panel-body">
          {definition([
            ["Username", user.username],
            ["Role", label(user.role)],
          ])}
        </div>
      </Panel>
      <div className="actions settings-session-actions">
        <button onClick={() => setChanging(true)}>Change my password</button>
      </div>
      {changing && (
        <Modal title="Change password" close={() => setChanging(false)}>
          <PasswordChange
            onChanged={() =>
              window.dispatchEvent(new Event("ttx-session-expired"))
            }
          />
        </Modal>
      )}
      {user.role === "administrator" && <AdminSettings user={user} />}
    </>
  );
}

type ExperimentRow = {
  experiment: string;
  method: string;
  condition: string;
  precision?: number;
  recall?: number;
  f1?: number;
  false_positive_rate?: number;
  tp?: number;
  fp?: number;
  tn?: number;
  fn?: number;
  seconds?: number;
  correlation_seconds?: number;
  throughput?: number;
  peak_mib?: number;
  order_errors?: number;
  score?: number;
  result?: string;
  events?: number;
  relationships?: number;
};
type Results = {
  available: boolean;
  seed: number;
  generated_at: string;
  descriptions: Record<string, string>;
  limitations: string[];
  rows: ExperimentRow[];
  configuration: Record<string, string | number>;
};
type Estimate = { mean: number; sample_sd: number };
type MultiSeed = {
  available: boolean;
  seeds: number[];
  summary: {
    experiment: string;
    method: string;
    precision: Estimate;
    recall: Estimate;
    f1: Estimate;
    false_positive_rate: Estimate;
  }[];
};

const researchMetrics = [
  ["Precision", "precision"],
  ["Recall", "recall"],
  ["F1-score", "f1"],
] as const;
const number = (value?: number) =>
  value === undefined ? "—" : value.toFixed(3);
const percent = (value?: number) =>
  value === undefined ? "—" : (value * 100).toFixed(1) + "%";

function BenchmarkChart({
  rows,
  runtime,
}: {
  rows: ExperimentRow[];
  runtime: boolean;
}) {
  const measures = runtime
    ? ([
        ["Total runtime", "seconds"],
        ["Correlation", "correlation_seconds"],
      ] as const)
    : researchMetrics;
  const maximum = runtime
    ? Math.max(1, ...rows.map((row) => row.seconds ?? 0))
    : 1;
  const showMethod = new Set(rows.map(({ method }) => method)).size > 1;
  return (
    <div className="benchmark-chart">
      {rows.map((row) => (
        <div key={row.method + ":" + row.condition} className="benchmark-row">
          <strong>{showMethod ? label(row.method) : row.condition}</strong>
          <div className="benchmark-measures">
            {measures.map(([title, key]) => (
              <div key={key} className={"benchmark-measure " + key}>
                <span>{title}</span>
                <meter
                  min={0}
                  max={maximum}
                  value={row[key] ?? 0}
                  aria-label={
                    title + " for " + (showMethod ? row.method : row.condition)
                  }
                />
                <strong>
                  {runtime ? number(row[key]) + " s" : percent(row[key])}
                </strong>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

export function Research() {
  const state = useData<Results>("/research");
  const multi = useData<MultiSeed>("/research/multi-seed");
  const action = useAction();
  const [experiment, setExperiment] = useState("detection");
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">
            <FlaskConical size={15} /> SYNTHETIC EVALUATION
          </span>
          <h1>Research Lab</h1>
          <p>
            Recorded detection, correlation and evidence-handling benchmarks.
          </p>
        </div>
        <div className="actions">
          {["csv", "json"].map((format) => (
            <button
              key={format}
              disabled={!state.data?.available || action.busy}
              onClick={() =>
                void action.run(() =>
                  download(
                    "/research/" + format,
                    "threattrace-results." + format,
                    "GET",
                  ),
                )
              }
            >
              <Download size={16} /> Results {format.toUpperCase()}
            </button>
          ))}
        </div>
      </div>
      <Feedback error={action.error} />
      <Load state={state}>
        {(data) => {
          if (!data.available)
            return (
              <Panel title="Experiment results">
                <Empty>No recorded benchmark results are available.</Empty>
              </Panel>
            );
          const rows = data.rows.filter((row) => row.experiment === experiment);
          const scores = rows.some((row) => row.f1 !== undefined);
          const runtime = experiment === "scalability";
          const errors = rows.some((row) => row.order_errors !== undefined);
          const baseHeaders = ["Method", "Condition"];
          return (
            <>
              <div className="stat-summary research-stats">
                <div>
                  <strong>{data.configuration.scenarios}</strong>
                  <small>Synthetic scenarios</small>
                </div>
                <div>
                  <strong>{Object.keys(data.descriptions).length}</strong>
                  <small>Experiment groups</small>
                </div>
                <div>
                  <strong>{data.rows.length}</strong>
                  <small>Measured conditions</small>
                </div>
                <div>
                  <strong>{data.seed}</strong>
                  <small>Primary run seed</small>
                </div>
              </div>
              <Panel
                title="Recorded experiment"
                hint={date(data.generated_at) + " UTC"}
                action={
                  <select
                    aria-label="Experiment"
                    value={experiment}
                    onChange={(event) => setExperiment(event.target.value)}
                  >
                    {Object.keys(data.descriptions).map((name) => (
                      <option key={name} value={name}>
                        {label(name)}
                      </option>
                    ))}
                  </select>
                }
              >
                <p className="benchmark-description">
                  {data.descriptions[experiment]}
                </p>
                {(scores || runtime) && (
                  <BenchmarkChart rows={rows} runtime={runtime} />
                )}
              </Panel>
              <Panel
                title="Measured results"
                hint={
                  scores
                    ? "Precision, recall, F1 and false-positive rates are shown as percentages."
                    : runtime
                      ? "Recorded wall time, correlation time, throughput and memory."
                      : undefined
                }
              >
                <Table
                  headers={
                    scores
                      ? [
                          ...baseHeaders,
                          "Precision",
                          "Recall",
                          "F1-score",
                          "False-positive rate",
                          "TP / FP / TN / FN",
                          ...(errors ? ["Order errors"] : []),
                        ]
                      : runtime
                        ? [
                            "Condition",
                            "Events",
                            "Total runtime (s)",
                            "Correlation (s)",
                            "Events/s",
                            "Peak MiB",
                            "Relationships",
                          ]
                        : [...baseHeaders, "Outcome", "Score"]
                  }
                  rows={rows.map((row) =>
                    scores
                      ? [
                          row.method,
                          row.condition,
                          percent(row.precision),
                          percent(row.recall),
                          percent(row.f1),
                          percent(row.false_positive_rate),
                          [row.tp, row.fp, row.tn, row.fn].join(" / "),
                          ...(errors ? [row.order_errors ?? "—"] : []),
                        ]
                      : runtime
                        ? [
                            row.condition,
                            row.events?.toLocaleString(),
                            number(row.seconds),
                            number(row.correlation_seconds),
                            number(row.throughput),
                            number(row.peak_mib),
                            row.relationships?.toLocaleString(),
                          ]
                        : [
                            row.method,
                            row.condition,
                            row.result ? <Badge value={row.result} /> : "—",
                            row.score ?? "—",
                          ],
                  )}
                />
              </Panel>
              <Load state={multi}>
                {(recorded) => {
                  if (!recorded.available) return null;
                  const methods = recorded.summary.filter((row) =>
                    experiment === "detection" || experiment === "correlation"
                      ? row.experiment === experiment
                      : true,
                  );
                  const estimate = (metric: Estimate) =>
                    percent(metric.mean) +
                    " ± " +
                    (metric.sample_sd * 100).toFixed(1) +
                    " pp";
                  return (
                    <Panel
                      title="Multi-seed baseline comparison"
                      hint={
                        "Mean ± sample standard deviation · Seeds " +
                        recorded.seeds.join(", ")
                      }
                    >
                      <Table
                        headers={[
                          "Experiment",
                          "Method",
                          "Precision",
                          "Recall",
                          "F1-score",
                          "False-positive rate",
                        ]}
                        rows={methods.map((row) => [
                          label(row.experiment),
                          row.method,
                          estimate(row.precision),
                          estimate(row.recall),
                          estimate(row.f1),
                          estimate(row.false_positive_rate),
                        ])}
                      />
                    </Panel>
                  );
                }}
              </Load>
              <div className="chart-grid equal">
                <Panel title="Experimental conditions">
                  <div className="panel-body">
                    {definition(
                      Object.entries(data.configuration).map(([key, value]) => [
                        label(key),
                        value,
                      ]),
                    )}
                  </div>
                </Panel>
                <Panel title="Research limitations">
                  <ul className="research-limitations">
                    {data.limitations.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </Panel>
              </div>
            </>
          );
        }}
      </Load>
    </>
  );
}
