import { useState } from "react";
import { Download, FlaskConical, Save, ShieldCheck } from "lucide-react";
import { api, download } from "./api";
import type { Case, Page, Rule, User } from "./api";
import { Bars } from "./analysisViews";
import {
  Badge,
  date,
  definition,
  Empty,
  Feedback,
  formData,
  label,
  Load,
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
function AdminSettings() {
  const list = useData<User[]>("/users");
  const cases = useData<Page<Case>>("/cases?limit=200");
  const add = useAction(),
    access = useAction();
  return (
    <div className="chart-grid equal">
      <Panel title="Local accounts">
        <div className="panel-body">
          <Load state={list}>
            {(items) => (
              <ul>
                {items.map((user) => (
                  <li key={user.id}>
                    {user.username} · {user.role}
                  </li>
                ))}
              </ul>
            )}
          </Load>
          <form
            className="form room"
            onSubmit={(event) => {
              const form = event.currentTarget;
              const data = formData(event);
              void add.run(async () => {
                await api("/users", "POST", Object.fromEntries(data));
                list.refresh();
                form.reset();
              }, "Local account created.");
            }}
          >
            <label>
              New username
              <input name="username" required minLength={3} />
            </label>
            <label>
              Temporary password
              <input
                type="password"
                name="password"
                required
                minLength={12}
                autoComplete="new-password"
              />
            </label>
            <label>
              Role
              <select name="role">
                <option>investigator</option>
                <option>administrator</option>
              </select>
            </label>
            <Feedback message={add.message} error={add.error} />
            <button className="primary" disabled={add.busy}>
              Create account
            </button>
          </form>
        </div>
      </Panel>
      <Panel
        title="Case access"
        hint="Share or revoke a selected investigation for a local user"
      >
        <div className="panel-body">
          <form
            className="form"
            onSubmit={(event) => {
              const data = formData(event);
              const method = String(data.get("operation"));
              if (
                method === "DELETE" &&
                !window.confirm("Revoke access for this user?")
              )
                return;
              void access.run(async () => {
                await api(
                  "/cases/" + data.get("case") + "/access/" + data.get("user"),
                  method,
                );
              }, "Case access updated.");
            }}
          >
            <label>
              Case
              <select name="case" required>
                <option value="">Select a case</option>
                {cases.data?.items.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.title}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Account
              <select name="user" required>
                <option value="">Select an account</option>
                {list.data?.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.username}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Operation
              <select name="operation">
                <option value="PUT">Grant access</option>
                <option value="DELETE">Revoke access</option>
              </select>
            </label>
            <Feedback
              error={access.error ?? cases.error}
              message={access.message}
            />
            <button className="primary" disabled={access.busy}>
              Apply permission
            </button>
          </form>
        </div>
      </Panel>
    </div>
  );
}
export function SettingsView({ user }: { user: User }) {
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
      {user.role === "administrator" && <AdminSettings />}
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
export function Research() {
  const state = useData<Results>("/research");
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
            Reproducible measurements of evidence-aware forensic reconstruction.
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
              <Download size={16} /> {format.toUpperCase()}
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
                <Empty>
                  Run the reproducible experiment suite to populate this
                  workspace.
                </Empty>
              </Panel>
            );
          const rows = data.rows.filter((row) => row.experiment === experiment);
          const perf = rows.some((row) => row.f1 !== undefined);
          const runtime = experiment === "scalability";
          const metric = (value?: number) =>
            value === undefined ? "—" : value.toFixed(3);
          return (
            <>
              <div className="stat-summary">
                <div>
                  <strong>{data.seed}</strong>
                  <small>Random seed</small>
                </div>
                <div>
                  <strong>{Object.keys(data.descriptions).length}</strong>
                  <small>Experiment groups</small>
                </div>
                <div>
                  <strong>{data.rows.length}</strong>
                  <small>Measured conditions</small>
                </div>
              </div>
              <div className="chart-grid equal">
                <Panel
                  title="Experiment selection"
                  hint={"Recorded " + date(data.generated_at) + " UTC"}
                >
                  <div className="panel-body">
                    <label className="filter">
                      <span>Experiment</span>
                      <select
                        value={experiment}
                        onChange={(event) => setExperiment(event.target.value)}
                      >
                        {Object.keys(data.descriptions).map((name) => (
                          <option key={name} value={name}>
                            {label(name)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <p>{data.descriptions[experiment]}</p>
                  </div>
                </Panel>
                <Panel
                  title={
                    perf
                      ? "F1 by measured condition"
                      : runtime
                        ? "Processing seconds"
                        : "Confidence index or verification outcome"
                  }
                >
                  <Bars
                    values={rows.flatMap((row) => {
                      const value = perf
                        ? row.f1
                        : runtime
                          ? row.seconds
                          : (row.score ??
                            (row.result === undefined
                              ? undefined
                              : Number(row.result === "pass")));
                      return value === undefined
                        ? []
                        : [
                            [row.method + " · " + row.condition, value] as [
                              string,
                              number,
                            ],
                          ];
                    })}
                  />
                </Panel>
              </div>
              <Panel title="Measured results">
                <Table
                  headers={
                    perf
                      ? [
                          "Method",
                          "Condition",
                          "Precision",
                          "Recall",
                          "F1",
                          "FPR",
                          "TP / FP / TN / FN",
                          "Order errors",
                        ]
                      : runtime
                        ? [
                            "Events",
                            "Runtime (s)",
                            "Correlation (s)",
                            "Events/s",
                            "Peak MiB",
                          ]
                        : ["Method", "Condition", "Outcome", "Score"]
                  }
                  rows={rows.map((row) =>
                    perf
                      ? [
                          row.method,
                          row.condition,
                          metric(row.precision),
                          metric(row.recall),
                          metric(row.f1),
                          metric(row.false_positive_rate),
                          [row.tp, row.fp, row.tn, row.fn].join(" / "),
                          row.order_errors ?? "—",
                        ]
                      : runtime
                        ? [
                            row.events,
                            metric(row.seconds),
                            metric(row.correlation_seconds),
                            metric(row.throughput),
                            metric(row.peak_mib),
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
              <div className="chart-grid equal">
                <Panel title="Dataset and baseline configuration">
                  <div className="panel-body">
                    {definition(
                      Object.entries(data.configuration).map(([key, value]) => [
                        label(key),
                        value,
                      ]),
                    )}
                  </div>
                </Panel>
                <Panel title="Experimental limitations">
                  <div className="panel-body">
                    <ul>
                      {data.limitations.map((line) => (
                        <li key={line}>{line}</li>
                      ))}
                    </ul>
                  </div>
                </Panel>
              </div>
            </>
          );
        }}
      </Load>
    </>
  );
}
