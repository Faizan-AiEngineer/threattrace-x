import { useState } from "react";
import {
  Download,
  FileText,
  GitBranch,
  Minus,
  Network,
  Plus,
} from "lucide-react";
import { api, download, query } from "./api";
import type { Edge, Indicator, Page } from "./api";
import { base, link } from "./workspace";
import {
  Badge,
  bytes,
  date,
  definition,
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

type Node = {
  id: string;
  action: string;
  hostname: string | null;
  username: string | null;
  evidence_id: string;
  source_ref: string;
  timestamp: string | null;
  entities: [string, string][];
};
type Attachment = {
  event_id: string;
  id: string;
  label: string;
  kind: "finding" | "indicator";
};
type Graph = {
  nodes: Node[];
  edges: Edge[];
  attachments: Attachment[];
  limited: boolean;
};
type EntityNode = {
  kind: string;
  label: string;
  id: string;
  events: Map<string, Node>;
};
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

function Relationship({
  id,
  edge,
  changed,
}: {
  id: string;
  edge: Edge;
  changed: () => void;
}) {
  const action = useAction();
  return (
    <div className="selected-link">
      <h3>{label(edge.kind)} relationship</h3>
      <p>
        {edge.explanation} · {Math.round(edge.confidence * 100)}% confidence
        index · v{edge.version}
      </p>
      <p>
        {edge.attributes
          .map((attribute) => attribute.kind + " · " + attribute.value)
          .join(", ")}
      </p>
      <p>
        <a href={link(id, "events", edge.source_id)}>Earlier event</a> ·{" "}
        <a href={link(id, "events", edge.target_id)}>Later event</a>
      </p>
      <form
        className="form"
        onSubmit={(event) => {
          const data = formData(event);
          void action.run(async () => {
            await api(
              base(id) + "/correlation/" + edge.id,
              "PATCH",
              Object.fromEntries(data),
            );
            changed();
          }, "Relationship review saved.");
        }}
      >
        <label>
          Review
          <select name="review" defaultValue={edge.review}>
            {["pending", "confirmed", "rejected"].map((option) => (
              <option key={option} value={option}>
                {label(option)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Reason
          <textarea
            name="reason"
            required
            defaultValue={edge.reason}
            rows={2}
          />
        </label>
        <Feedback error={action.error} message={action.message} />
        <button className="primary" disabled={action.busy}>
          Save relationship review
        </button>
      </form>
    </div>
  );
}

function EntityMap({
  graph,
  id,
  type,
}: {
  graph: Graph;
  id: string;
  type: string;
}) {
  const [selected, setSelected] = useState("");
  const lookup = new Map<string, EntityNode>();
  const byEvent = new Map(graph.nodes.map((event) => [event.id, event]));
  function attach(kind: string, name: string, key: string, event: Node) {
    const entityKey = kind + ":" + key;
    const entry = lookup.get(entityKey) ?? {
      kind,
      label: name,
      id: key,
      events: new Map<string, Node>(),
    };
    entry.events.set(event.id, event);
    lookup.set(entityKey, entry);
  }
  for (const event of graph.nodes) {
    for (const [kind, value] of event.entities)
      attach(kind, value, value, event);
  }
  for (const row of graph.attachments) {
    const event = byEvent.get(row.event_id);
    if (event) attach(row.kind, row.label, row.id, event);
  }
  const entities = [...lookup.entries()]
    .filter(([, entity]) => !type || entity.kind === type)
    .sort(
      ([, left], [, right]) =>
        right.events.size - left.events.size ||
        left.label.localeCompare(right.label),
    );
  if (!entities.length)
    return (
      <Empty>
        No entities of this type appear in the selected relationships.
      </Empty>
    );
  const active = lookup.get(selected) ?? entities[0][1];
  return (
    <div className="graph-layout">
      <div className="entity-map">
        <div className="entity-node-list" aria-label="Entity graph nodes">
          {entities.slice(0, 36).map(([key, entity]) => (
            <button
              key={key}
              type="button"
              aria-pressed={active === entity}
              onClick={() => setSelected(key)}
            >
              <span>
                <small>{label(entity.kind)}</small>
                {entity.label}
              </span>
              <code>{entity.events.size}</code>
            </button>
          ))}
        </div>
        <div className="entity-edges">
          <GitBranch size={19} />
          <span>Observed source links</span>
        </div>
        <div className="entity-node-list" aria-label="Supporting event nodes">
          {[...active.events.values()].slice(0, 18).map((event) => (
            <a
              className="button"
              key={event.id}
              href={link(id, "events", event.id)}
            >
              <span>
                <small>{event.source_ref}</small>
                {label(event.action)}
              </span>
            </a>
          ))}
        </div>
      </div>
      <div className="graph-detail">
        <h3>{active.label}</h3>
        <p>
          {label(active.kind)} · {active.events.size} supporting events
        </p>
        {active.kind === "finding" && (
          <p>
            <a href={link(id, "findings", active.id)}>Inspect finding</a>
          </p>
        )}
        {active.kind === "indicator" && (
          <p>
            <a href={link(id, "intelligence")}>Open indicator register</a>
          </p>
        )}
        <h3>Evidence references</h3>
        <ul>
          {[
            ...new Set(
              [...active.events.values()].map((event) => event.evidence_id),
            ),
          ].map((evidence) => (
            <li key={evidence}>
              <a href={link(id, "evidence", evidence)}>{evidence}</a>
            </li>
          ))}
        </ul>
        {entities.length > 36 && (
          <p>Showing 36 entities. Select a type to narrow the view.</p>
        )}
      </div>
    </div>
  );
}

export function GraphView({ id }: { id: string }) {
  const [filter, setFilter] = useState("");
  const [view, setView] = useState("events");
  const [kind, setKind] = useState("");
  const [limit, setLimit] = useState(18);
  const [nodeId, setNode] = useState("");
  const [edgeId, setEdge] = useState("");
  const [zoom, setZoom] = useState(1);
  const state = useData<Graph>(
    base(id) + "/correlation" + query({ relationship: filter, kind, limit }),
  );
  return (
    <Panel
      title="Correlation graph"
      hint="Source observations and inferred event relationships"
      action={
        <div className="actions">
          <button
            className="icon-button"
            aria-label="Zoom out graph"
            onClick={() => setZoom(Math.max(1, zoom - 0.25))}
          >
            <Minus size={16} />
          </button>
          <button
            className="icon-button"
            aria-label="Zoom in graph"
            onClick={() => setZoom(Math.min(3, zoom + 0.25))}
          >
            <Plus size={16} />
          </button>
        </div>
      }
    >
      <div className="toolbar">
        <Select
          title="Graph view"
          choices={["events", "entities"]}
          value={view}
          onChange={setView}
        />
        <Select
          title="Relationship"
          all
          choices={["observed", "inferred"]}
          value={filter}
          onChange={setFilter}
        />
        <Select
          title="Entity type"
          all
          choices={[...entityKinds, "finding", "indicator"]}
          value={kind}
          onChange={setKind}
        />
        <label className="filter">
          <span>Relationship limit</span>
          <select
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
          >
            {[18, 36, 72, 120].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <span className="graph-key">
          <i /> Observed <i /> Inferred
        </span>
      </div>
      <Load state={state}>
        {(data) => {
          if (!data.nodes.length)
            return (
              <Empty>
                No events match this graph view. Run case analysis to build
                relationships.
              </Empty>
            );
          if (view === "entities")
            return <EntityMap key={kind} graph={data} id={id} type={kind} />;
          const columns = Math.min(
            5,
            Math.max(2, Math.ceil(Math.sqrt(data.nodes.length))),
          );
          const height = Math.max(
            360,
            Math.ceil(data.nodes.length / columns) * 104 + 18,
          );
          const points = new Map(
            data.nodes.map((node, index) => [
              node.id,
              {
                x: (((index % columns) + 0.5) * 760) / columns,
                y: 64 + Math.floor(index / columns) * 104,
              },
            ]),
          );
          const current = data.nodes.find((node) => node.id === nodeId);
          const edge = data.edges.find((item) => item.id === edgeId);
          return (
            <div className="graph-layout">
              <div
                className="graph-scroll"
                tabIndex={0}
                aria-label="Scrollable graph"
              >
                <svg
                  viewBox={"0 0 760 " + height}
                  style={{ width: 100 * zoom + "%", minWidth: 560 }}
                  aria-label="Event correlation diagram"
                >
                  {data.edges.map((record) => {
                    const from = points.get(record.source_id),
                      to = points.get(record.target_id);
                    if (!from || !to) return null;
                    return (
                      <g key={record.id}>
                        <line
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          className={
                            "graph-edge " +
                            record.kind +
                            (edgeId === record.id ? " selected" : "")
                          }
                        />
                        <line
                          x1={from.x}
                          y1={from.y}
                          x2={to.x}
                          y2={to.y}
                          className="graph-hit"
                          onClick={() => setEdge(record.id)}
                        >
                          <title>{record.explanation}</title>
                        </line>
                      </g>
                    );
                  })}
                  {data.nodes.map((node, index) => {
                    const { x, y } = points.get(node.id)!;
                    return (
                      <g
                        role="button"
                        aria-label={
                          "Select event " +
                          (index + 1) +
                          " " +
                          label(node.action)
                        }
                        tabIndex={0}
                        key={node.id}
                        transform={"translate(" + x + "," + y + ")"}
                        onClick={() => {
                          setNode(node.id);
                          setEdge("");
                        }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setNode(node.id);
                            setEdge("");
                          }
                        }}
                        className={
                          "graph-node " + (nodeId === node.id ? "selected" : "")
                        }
                      >
                        <rect x="-57" y="-20" width="114" height="40" rx="7" />
                        <text textAnchor="middle" y="4">
                          {label(node.action).slice(0, 17)}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
              <div className="graph-detail">
                {current ? (
                  <>
                    <h3>{label(current.action)}</h3>
                    {definition([
                      ["Host", current.hostname],
                      ["Account", current.username],
                      ["UTC", date(current.timestamp)],
                      [
                        "Source reference",
                        <a href={link(id, "evidence", current.evidence_id)}>
                          {current.source_ref}
                        </a>,
                      ],
                    ])}
                    <p>
                      <a href={link(id, "events", current.id)}>Inspect event</a>
                    </p>
                    <h3>Entities</h3>
                    <ul>
                      {current.entities.map(([type, value]) => (
                        <li key={type + value}>
                          {label(type)} · {value}
                        </li>
                      ))}
                    </ul>
                  </>
                ) : (
                  <>
                    <GitBranch size={21} />
                    <h3>Graph selection</h3>
                    <p>Select an event to inspect entities and evidence.</p>
                  </>
                )}
                {current &&
                  data.attachments
                    .filter((row) => row.event_id === current.id)
                    .map((row) => (
                      <p key={row.kind + row.id}>
                        <a
                          href={
                            row.kind === "finding"
                              ? link(id, "findings", row.id)
                              : link(id, "intelligence")
                          }
                        >
                          {label(row.kind)} · {row.label}
                        </a>
                      </p>
                    ))}
                <label className="filter">
                  <span>Select relationship</span>
                  <select
                    value={edgeId}
                    onChange={(event) => setEdge(event.target.value)}
                  >
                    <option value="">Choose relationship</option>
                    {data.edges.map((record, index) => (
                      <option key={record.id} value={record.id}>
                        {index + 1}. {label(record.kind)} ·{" "}
                        {Math.round(record.confidence * 100)}%
                      </option>
                    ))}
                  </select>
                </label>
                {edge && (
                  <Relationship
                    key={edge.id}
                    id={id}
                    edge={edge}
                    changed={state.refresh}
                  />
                )}
                {data.limited && (
                  <p className="muted">
                    Result capped. Increase the limit or filter entities.
                  </p>
                )}
              </div>
            </div>
          );
        }}
      </Load>
    </Panel>
  );
}
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
    ["events.csv", "Timeline CSV"],
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
