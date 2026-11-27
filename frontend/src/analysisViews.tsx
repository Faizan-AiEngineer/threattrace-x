import { useState } from "react";
import { Download, FileText, Network, Plus } from "lucide-react";
import { api, download, query } from "./api";
import type { Indicator, Page } from "./api";
import { base, link } from "./workspace";
import {
  Badge,
  bytes,
  date,
  Empty,
  Feedback,
  formData,
  label,
  Load,
  Modal,
  Pager,
  Panel,
  Select,
  Table,
  useAction,
  useData,
} from "./ui";

type Entity = { id: string; kind: string; value: string; event_ids: string[] };
const entityKinds = [
  "account",
  "host",
  "ip",
  "process",
  "process_id",
  "file",
  "hash",
  "domain",
  "url",
];

export function EntitiesView({ id }: { id: string }) {
  const [filters, set] = useState({ kind: "", q: "", page: 1 });
  const state = useData<Page<Entity>>(base(id) + "/entities" + query(filters));
  return (
    <Panel
      title="Associated entities"
      hint="Normalized entities derived from case events"
    >
      <div className="toolbar">
        <label className="filter">
          <span>Search</span>
          <input
            value={filters.q}
            onChange={(event) =>
              set({ ...filters, q: event.target.value, page: 1 })
            }
          />
        </label>
        <Select
          title="Type"
          all
          choices={entityKinds}
          value={filters.kind}
          onChange={(kind) => set({ ...filters, kind, page: 1 })}
        />
      </div>
      <Load state={state}>
        {(data) => (
          <>
            <Table
              headers={["Type", "Value", "Supporting events"]}
              rows={data.items.map((row) => [
                label(row.kind),
                <code>{row.value}</code>,
                <span className="event-links">
                  {row.event_ids.map((value, index) => (
                    <a key={value} href={link(id, "events", value)}>
                      {index + 1}
                    </a>
                  ))}
                </span>,
              ])}
            />
            <Pager data={data} go={(page) => set({ ...filters, page })} />
          </>
        )}
      </Load>
    </Panel>
  );
}
type NetworkSummary = {
  records: number;
  bytes: number;
  matches: number;
  protocols: [string, number][];
  sources: [string, number][];
  destinations: [string, number][];
  ports: [string, number][];
  dns: [string, number][];
  flows: {
    source: string;
    destination: string;
    protocol: string;
    source_port: number | null;
    destination_port: number | null;
    records: number;
  }[];
};
export function Bars({ values }: { values: [string, number][] }) {
  const max = Math.max(1, ...values.map(([, value]) => value));
  return values.length ? (
    <div className="bars">
      {values.map(([name, value]) => (
        <div key={name}>
          <span title={name}>{name}</span>
          <div>
            <i style={{ width: (100 * value) / max + "%" }} />
          </div>
          <strong>{Number.isInteger(value) ? value : value.toFixed(3)}</strong>
        </div>
      ))}
    </div>
  ) : (
    <Empty />
  );
}
export function NetworkView({ id }: { id: string }) {
  const state = useData<NetworkSummary>(base(id) + "/network");
  return (
    <Load state={state}>
      {(data) => (
        <>
          <div className="stat-summary">
            {[
              [data.records, "Network records"],
              [bytes(data.bytes), "Reported volume"],
              [data.matches, "Indicator matches"],
            ].map(([value, title]) => (
              <div key={title}>
                <strong>{value}</strong>
                <small>{title}</small>
              </div>
            ))}
          </div>
          <div className="chart-grid equal">
            <Panel
              title="Protocol distribution"
              hint="Offline capture and normalized network metadata"
            >
              <Bars values={data.protocols} />
            </Panel>
            <Panel title="Destination addresses">
              <Bars values={data.destinations} />
            </Panel>
            <Panel title="Source addresses">
              <Bars values={data.sources} />
            </Panel>
            <Panel title="Destination ports">
              <Bars values={data.ports} />
            </Panel>
          </div>
          <Panel
            title="Communication flows"
            hint="Top directional flows grouped by address, ports and protocol"
          >
            <div className="panel-body flow-preview">
              {data.flows.slice(0, 4).map((row, index) => (
                <div key={index}>
                  <code>{row.source}</code>
                  <span>
                    <Network size={16} /> {row.records}
                  </span>
                  <code>{row.destination}</code>
                </div>
              ))}
            </div>
            <Table
              headers={[
                "Source",
                "Destination",
                "Protocol",
                "Destination port",
                "Records",
              ]}
              rows={data.flows.map((row) => [
                <code>{row.source}</code>,
                <code>{row.destination}</code>,
                row.protocol,
                row.destination_port ?? "—",
                row.records,
              ])}
            />
          </Panel>
          <Panel
            title="DNS questions"
            hint="Visible query metadata. Encrypted traffic can hide application-layer details."
          >
            <Bars values={data.dns} />
          </Panel>
        </>
      )}
    </Load>
  );
}
const indicatorKinds = [
  "ipv4",
  "ipv6",
  "domain",
  "url",
  "md5",
  "sha1",
  "sha256",
  "sha512",
];
export function IntelligenceView({ id }: { id: string }) {
  const [page, setPage] = useState(1);
  const [mode, setMode] = useState("");
  const path = base(id) + "/intelligence";
  const state = useData<Page<Indicator>>(path + query({ page }));
  const action = useAction();
  return (
    <Panel
      title="Threat intelligence"
      hint="Offline, case-specific indicators and exact matches"
      action={
        <div className="actions">
          <button onClick={() => setMode("import")}>Import JSON or CSV</button>
          <button className="primary" onClick={() => setMode("add")}>
            <Plus size={16} /> Add indicator
          </button>
        </div>
      }
    >
      {mode && (
        <Modal
          title={mode === "add" ? "Add indicator" : "Import indicators"}
          close={() => setMode("")}
        >
          <form
            className="form"
            onSubmit={(event) => {
              const form = formData(event);
              const payload =
                mode === "import"
                  ? form
                  : {
                      ...Object.fromEntries(form),
                      confidence: Number(form.get("confidence")),
                      expires_at: form.get("expires_at") || null,
                      tags: String(form.get("tags"))
                        .split(",")
                        .map((value) => value.trim())
                        .filter(Boolean),
                    };
              void action.run(async () => {
                await api(
                  path + (mode === "import" ? "/import" : ""),
                  "POST",
                  payload,
                );
                state.refresh();
                setMode("");
              });
            }}
          >
            {mode === "import" ? (
              <label>
                Indicator file
                <input type="file" name="file" accept=".csv,.json" required />
              </label>
            ) : (
              <>
                <label>
                  Type
                  <select name="kind">
                    {indicatorKinds.map((type) => (
                      <option key={type}>{type}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Indicator value
                  <input name="value" required />
                </label>
                <label>
                  Source
                  <input name="source" required />
                </label>
                <label>
                  Confidence (0–100)
                  <input
                    name="confidence"
                    type="number"
                    min={0}
                    max={100}
                    required
                    defaultValue={50}
                  />
                </label>
                <label>
                  Expires at (ISO time with timezone)
                  <input name="expires_at" />
                </label>
                <label>
                  Description
                  <textarea name="description" rows={2} />
                </label>
                <label>
                  Tags, comma separated
                  <input name="tags" />
                </label>
              </>
            )}
            <Feedback error={action.error} />
            <button className="primary" disabled={action.busy}>
              {mode === "add" ? "Save indicator" : "Import indicators"}
            </button>
          </form>
        </Modal>
      )}
      <Load state={state}>
        {(data) => (
          <>
            <Table
              headers={[
                "Indicator",
                "Source",
                "Confidence",
                "Expiry (UTC)",
                "Matching events",
              ]}
              rows={data.items.map((row) => [
                <span className="cell-title">
                  <code>{row.value}</code>
                  <small>
                    {row.kind} · {row.tags.join(", ")}
                  </small>
                </span>,
                <span>
                  {row.source}
                  <small>{row.description}</small>
                </span>,
                row.confidence,
                date(row.expires_at),
                row.match_count ? (
                  <details>
                    <summary>{row.match_count} exact matches</summary>
                    <span className="event-links">
                      {row.event_ids.map((value, index) => (
                        <a key={value} href={link(id, "events", value)}>
                          {index + 1}
                        </a>
                      ))}
                    </span>
                  </details>
                ) : (
                  "0"
                ),
              ])}
            />
            <Pager data={data} go={setPage} />
          </>
        )}
      </Load>
    </Panel>
  );
}
type Report = {
  id: string;
  format: string;
  timestamp: string;
  actor: string;
  sha256: string;
};
export function ReportsView({ id }: { id: string }) {
  const [page, setPage] = useState(1);
  const path = base(id) + "/reports";
  const state = useData<Page<Report>>(path + query({ page }));
  const action = useAction();
  const formats = [
    ["pdf", "PDF report"],
    ["html", "HTML report"],
    ["json", "JSON snapshot"],
    ["events.csv", "Full-case timeline CSV"],
    ["findings.csv", "Findings CSV"],
  ];
  return (
    <>
      <Panel
        title="Generate report"
        hint="Export a case snapshot with evidence, methodology, findings and limitations"
      >
        <div className="panel-body">
          <div className="report-options">
            {formats.map(([format, title]) => (
              <button
                key={format}
                disabled={action.busy}
                onClick={() =>
                  void action.run(async () => {
                    await download(
                      path + "/" + format,
                      "threattrace-" +
                        (format.includes(".") ? format : "report." + format),
                    );
                    state.refresh();
                  }, "Report exported and recorded in custody history.")
                }
              >
                <FileText size={20} />
                <strong>{title}</strong>
                <Download size={17} />
              </button>
            ))}
          </div>
          <Feedback error={action.error} message={action.message} />
        </div>
      </Panel>
      <Panel title="Export history">
        <Load state={state}>
          {(data) => (
            <>
              <Table
                headers={["Date (UTC)", "Actor", "Format", "SHA-256"]}
                rows={data.items.map((row) => [
                  date(row.timestamp),
                  row.actor,
                  <Badge value={row.format} />,
                  <code>{row.sha256}</code>,
                ])}
              />
              <Pager data={data} go={setPage} />
            </>
          )}
        </Load>
      </Panel>
    </>
  );
}
