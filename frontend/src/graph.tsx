import { useRef, useState } from "react";
import type { KeyboardEvent, PointerEvent } from "react";
import {
  Activity,
  CircleAlert,
  Crosshair,
  FileText,
  Fingerprint,
  Globe2,
  Maximize,
  Minus,
  Monitor,
  Network,
  Plus,
  Server,
  UserRound,
} from "lucide-react";
import { api, query } from "./api";
import type { Edge } from "./api";
import { base, link } from "./workspace";
import {
  Badge,
  date,
  Empty,
  Feedback,
  formData,
  label,
  Load,
  Panel,
  Select,
  useAction,
  useData,
} from "./ui";

type Node = {
  id: string;
  action: string;
  category: string;
  severity: string;
  outcome: string | null;
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
  sources: Record<string, string>;
};

type Subject = {
  key: string;
  kind: string;
  value: string;
  ref?: string;
  events: Node[];
};
type Position = { x: number; y: number };
type Selection = { type: "event" | "subject" | "relationship"; key: string };

const kinds = {
  ip: { name: "IP address", icon: Network, color: "#58cee7", shape: "diamond" },
  account: {
    name: "Account",
    icon: UserRound,
    color: "#c5a4f6",
    shape: "circle",
  },
  device: { name: "Device", icon: Monitor, color: "#7ee0ad", shape: "square" },
  host: { name: "Host", icon: Server, color: "#82aef7", shape: "hex" },
  file: { name: "File", icon: FileText, color: "#f1bf73", shape: "page" },
  event: {
    name: "Security event",
    icon: Activity,
    color: "#dbecf9",
    shape: "square",
  },
  evidence: {
    name: "Evidence source",
    icon: Fingerprint,
    color: "#89d8bc",
    shape: "page",
  },
  finding: {
    name: "Finding",
    icon: CircleAlert,
    color: "#f49ca0",
    shape: "diamond",
  },
  indicator: {
    name: "Indicator",
    icon: Crosshair,
    color: "#f6ce79",
    shape: "circle",
  },
  domain: { name: "Domain", icon: Globe2, color: "#9fc3f6", shape: "circle" },
  url: { name: "URL", icon: Globe2, color: "#9fc3f6", shape: "circle" },
};
const primaryKinds = [
  "ip",
  "account",
  "device",
  "host",
  "file",
  "event",
] as const;
function styleFor(kind: string) {
  return (
    kinds[kind as keyof typeof kinds] ?? {
      name: label(kind),
      icon: Fingerprint,
      color: "#aabed4",
      shape: "square",
    }
  );
}

function eventTitle(node: Node) {
  if (node.action === "login" && node.outcome === "failure")
    return "Failed sign-in";
  if (node.action === "login" && node.outcome === "success")
    return "Successful sign-in";
  return label(node.action);
}

function subjectsFor(data: Graph) {
  const subjects = new Map<string, Subject>();
  const nodes = new Map(data.nodes.map((node) => [node.id, node]));
  function attach(kind: string, value: string, node: Node, ref?: string) {
    const key = kind + ":" + (ref ?? value);
    const subject = subjects.get(key) ?? { key, kind, value, ref, events: [] };
    if (!subject.events.includes(node)) subject.events.push(node);
    subjects.set(key, subject);
  }
  for (const node of data.nodes) {
    for (const [kind, value] of node.entities) attach(kind, value, node);
    attach(
      "evidence",
      data.sources[node.evidence_id] ?? "Evidence item",
      node,
      node.evidence_id,
    );
  }
  for (const attachment of data.attachments) {
    const node = nodes.get(attachment.event_id);
    if (node) attach(attachment.kind, attachment.label, node, attachment.id);
  }
  return [...subjects.values()].sort(
    (a, b) =>
      b.events.length - a.events.length || a.value.localeCompare(b.value),
  );
}

function shorten(value: string, length: number) {
  return value.length > length ? value.slice(0, length - 1) + "…" : value;
}

function Symbol({ kind }: { kind: string }) {
  const { icon: Icon, color, shape } = styleFor(kind);
  return (
    <g style={{ color }} fill="#172a40" stroke={color} strokeWidth="1.35">
      {shape === "diamond" ? (
        <path d="M0 -15 15 0 0 15 -15 0Z" />
      ) : shape === "circle" ? (
        <circle r="14" />
      ) : shape === "hex" ? (
        <path d="M-8 -13 8 -13 16 0 8 13 -8 13 -16 0Z" />
      ) : shape === "page" ? (
        <path d="M-12 -15H6L13 -8V15H-12Z" />
      ) : (
        <rect x="-14" y="-14" width="28" height="28" rx="4" />
      )}
      <Icon
        x={-8}
        y={-8}
        width={16}
        height={16}
        fill="none"
        strokeWidth={1.9}
      />
    </g>
  );
}

function ForensicNode({
  point,
  kind,
  title,
  subtitle,
  selected,
  actionLabel,
  choose,
}: {
  point: Position;
  kind: string;
  title: string;
  subtitle: string;
  selected: boolean;
  actionLabel: string;
  choose: () => void;
}) {
  return (
    <g
      role="button"
      aria-label={actionLabel}
      aria-pressed={selected}
      tabIndex={0}
      className="forensic-node"
      data-kind={kind}
      data-selected={selected}
      transform={"translate(" + point.x + "," + point.y + ")"}
      onClick={choose}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          event.stopPropagation();
          choose();
        }
      }}
    >
      <title>{title + " · " + subtitle}</title>
      <rect
        className="node-frame"
        x="-102"
        y="-24"
        width="204"
        height="48"
        rx="7"
      />
      <g transform="translate(-79,0)">
        <Symbol kind={kind} />
      </g>
      <text x="-58" y="-3" className="node-title">
        {shorten(title, 22)}
      </text>
      <text x="-58" y="13" className="node-subtitle">
        {shorten(subtitle, 25)}
      </text>
    </g>
  );
}

function grid(
  rows: { key: string }[],
  top: number,
  spacing: number,
  width: number,
) {
  const columns = Math.min(4, rows.length || 1);
  const inset = (width - 240 * columns) / 2;
  return new Map(
    rows.map(({ key }, index) => [
      key,
      {
        x: inset + 120 + 240 * (index % columns),
        y: top + Math.floor(index / columns) * spacing,
      },
    ]),
  );
}

function attachmentCurve(from: Position, to: Position) {
  const y = (from.y + to.y) / 2;
  return (
    "M" +
    from.x +
    "," +
    (from.y + 24) +
    " C" +
    from.x +
    "," +
    y +
    " " +
    to.x +
    "," +
    y +
    " " +
    to.x +
    "," +
    (to.y - 24)
  );
}

function relationshipCurve(from: Position, to: Position, index: number) {
  if (from.y === to.y) {
    const arc = from.y - 40 - (index % 4) * 11;
    return (
      "M" +
      from.x +
      "," +
      (from.y - 23) +
      " C" +
      from.x +
      "," +
      arc +
      " " +
      to.x +
      "," +
      arc +
      " " +
      to.x +
      "," +
      (to.y - 24)
    );
  }
  const forward = to.y > from.y ? 1 : -1;
  const midpoint = (to.y + from.y) / 2 + ((index % 4) - 1.5) * 8;
  return (
    "M" +
    from.x +
    "," +
    (from.y + 24 * forward) +
    " C" +
    from.x +
    "," +
    midpoint +
    " " +
    to.x +
    "," +
    midpoint +
    " " +
    to.x +
    "," +
    (to.y - 24 * forward)
  );
}

function GraphCanvas({
  data,
  subjects,
  kind,
  selection,
  onSelect,
}: {
  data: Graph;
  subjects: Subject[];
  kind: string;
  selection: Selection;
  onSelect: (value: Selection) => void;
}) {
  const [view, setView] = useState({ x: 0, y: 0, zoom: 1 });
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{
    x: number;
    y: number;
    left: number;
    top: number;
    scale: number;
  } | null>(null);
  const positioned = (
    kind
      ? subjects.filter((row) => row.kind === kind)
      : subjects.filter(
          (row) =>
            row.kind !== "evidence" &&
            row.kind !== "process_id" &&
            row.kind !== "hash",
        )
  ).slice(0, 8);
  const sources = subjects
    .filter((row) => row.kind === "evidence" && row.kind !== kind)
    .slice(0, 4);
  const width = 1000;
  const eventTop = positioned.length
    ? 64 + Math.ceil(positioned.length / 4) * 75 + 35
    : 106;
  const sourceTop = eventTop + Math.ceil(data.nodes.length / 4) * 85 + 36;
  const height = sources.length ? sourceTop + 53 : sourceTop - 12;
  const points = grid(
    data.nodes.map(({ id }) => ({ key: id })),
    eventTop,
    85,
    width,
  );
  const subjectPoints = grid(positioned, 58, 75, width);
  const sourcePoints = grid(sources, sourceTop, 72, width);
  const linked =
    selection.type === "subject"
      ? subjects.find((row) => row.key === selection.key)?.events
      : undefined;
  const edge =
    selection.type === "relationship"
      ? data.edges.find((item) => item.id === selection.key)
      : undefined;
  const links = [...positioned, ...sources].flatMap((row) =>
    row.events
      .filter(
        (event) =>
          selection.key === row.key ||
          selection.key === event.id ||
          event.id === edge?.source_id ||
          event.id === edge?.target_id,
      )
      .map((event) => ({ row, event })),
  );
  function zoom(delta: number) {
    setView((current) => {
      const next = Math.max(0.65, Math.min(3.5, current.zoom + delta));
      return {
        x: current.x + (width / current.zoom - width / next) / 2,
        y: current.y + (height / current.zoom - height / next) / 2,
        zoom: next,
      };
    });
  }
  function beginPan(event: PointerEvent<SVGSVGElement>) {
    if (
      event.button !== 0 ||
      (event.target as Element).closest('[role="button"]')
    )
      return;
    const scale = svg.current?.getScreenCTM()?.a;
    if (!scale) return;
    drag.current = {
      x: event.clientX,
      y: event.clientY,
      left: view.x,
      top: view.y,
      scale,
    };
    event.currentTarget.setPointerCapture(event.pointerId);
  }
  function pan(event: PointerEvent<SVGSVGElement>) {
    const current = drag.current;
    if (!current) return;
    setView((previous) => ({
      ...previous,
      x: current.left - (event.clientX - current.x) / current.scale,
      y: current.top - (event.clientY - current.y) / current.scale,
    }));
  }
  function keyboardPan(event: KeyboardEvent<SVGSVGElement>) {
    const poses: Record<string, [number, number]> = {
      ArrowLeft: [-60, 0],
      ArrowRight: [60, 0],
      ArrowUp: [0, -60],
      ArrowDown: [0, 60],
    };
    const direction = poses[event.key];
    if (!direction) return;
    event.preventDefault();
    setView((current) => ({
      ...current,
      x: current.x + direction[0],
      y: current.y + direction[1],
    }));
  }
  return (
    <div className="graph-stage">
      <div className="graph-controls">
        <span>Drag to pan · source links follow your selection</span>
        <div className="actions">
          <button
            className="icon-button"
            aria-label="Zoom out graph"
            onClick={() => zoom(-0.25)}
          >
            <Minus size={16} />
          </button>
          <span className="graph-zoom" aria-label="Graph zoom">
            {Math.round(view.zoom * 100)}%
          </span>
          <button
            className="icon-button"
            aria-label="Zoom in graph"
            onClick={() => zoom(0.25)}
          >
            <Plus size={16} />
          </button>
          <button onClick={() => setView({ x: 0, y: 0, zoom: 1 })}>
            <Maximize size={15} /> Fit graph
          </button>
        </div>
      </div>
      <svg
        ref={svg}
        className="forensic-canvas"
        aria-label="Event correlation diagram"
        aria-description="Use arrow keys to pan. Tab to select a node or relationship."
        role="group"
        tabIndex={0}
        viewBox={[view.x, view.y, width / view.zoom, height / view.zoom].join(
          " ",
        )}
        onPointerDown={beginPan}
        onPointerMove={pan}
        onPointerUp={() => {
          drag.current = null;
        }}
        onPointerCancel={() => {
          drag.current = null;
        }}
        onLostPointerCapture={() => {
          drag.current = null;
        }}
        onKeyDown={keyboardPan}
      >
        <defs>
          <marker
            id="forensic-arrow-observed"
            viewBox="0 0 8 8"
            markerWidth="7"
            markerHeight="7"
            refX="7"
            refY="4"
            orient="auto"
          >
            <path d="M0 0 8 4 0 8Z" fill="#64c6d9" />
          </marker>
          <marker
            id="forensic-arrow-inferred"
            viewBox="0 0 8 8"
            markerWidth="7"
            markerHeight="7"
            refX="7"
            refY="4"
            orient="auto"
          >
            <path d="M0 0 8 4 0 8Z" fill="#c6a6f7" />
          </marker>
        </defs>
        {positioned.length > 0 && (
          <text className="graph-band-label" x="22" y="24">
            ENTITIES &amp; INDICATORS
          </text>
        )}
        <text className="graph-band-label" x="22" y={eventTop - 61}>
          SECURITY EVENTS · UTC ORDER
        </text>
        {sources.length > 0 && (
          <text className="graph-band-label" x="22" y={sourceTop - 43}>
            ORIGINAL EVIDENCE
          </text>
        )}
        {links.map(({ row, event }) => {
          const source = subjectPoints.get(row.key);
          const target = points.get(event.id)!;
          const evidence = sourcePoints.get(row.key);
          return (
            <path
              key={row.key + "/" + event.id}
              className="graph-provenance"
              d={
                source
                  ? attachmentCurve(source, target)
                  : attachmentCurve(target, evidence!)
              }
            />
          );
        })}
        {data.edges.map((edge, index) => {
          const path = relationshipCurve(
            points.get(edge.source_id)!,
            points.get(edge.target_id)!,
            index,
          );
          const active =
            selection.type === "relationship" && edge.id === selection.key;
          const choose = () => onSelect({ type: "relationship", key: edge.id });
          return (
            <g
              key={edge.id}
              role="button"
              tabIndex={0}
              aria-pressed={active}
              aria-label={
                "Select " + edge.kind + " relationship " + (index + 1)
              }
              className="forensic-link"
              onClick={choose}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  choose();
                }
              }}
            >
              <title>{edge.explanation}</title>
              <path
                className={"forensic-edge " + edge.kind}
                d={path}
                markerEnd={"url(#forensic-arrow-" + edge.kind + ")"}
              />
              <path className="forensic-edge-hit" d={path} />
            </g>
          );
        })}
        {[...positioned, ...sources].map((row) => (
          <ForensicNode
            key={row.key}
            point={(subjectPoints.get(row.key) ?? sourcePoints.get(row.key))!}
            kind={row.kind}
            title={row.value}
            subtitle={
              styleFor(row.kind).name + " · " + row.events.length + " events"
            }
            actionLabel={"Select " + styleFor(row.kind).name + " " + row.value}
            selected={selection.key === row.key}
            choose={() => onSelect({ type: "subject", key: row.key })}
          />
        ))}
        {data.nodes.map((node) => (
          <ForensicNode
            key={node.id}
            point={points.get(node.id)!}
            kind="event"
            title={eventTitle(node)}
            subtitle={[
              node.timestamp?.slice(11, 19) ?? "Undated",
              node.username ?? node.hostname ?? node.source_ref,
            ].join(" · ")}
            actionLabel={
              "Select event " + eventTitle(node) + " " + node.source_ref
            }
            selected={selection.key === node.id || !!linked?.includes(node)}
            choose={() => onSelect({ type: "event", key: node.id })}
          />
        ))}
      </svg>
    </div>
  );
}
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

function GraphResult({
  data,
  id,
  kind,
  mode,
  refresh,
}: {
  data: Graph;
  id: string;
  kind: string;
  mode: string;
  refresh: () => void;
}) {
  const subjects = subjectsFor(data);
  const visibleSubjects = subjects.filter((row) => !kind || row.kind === kind);
  const [picked, setPicked] = useState<Selection>();
  const selection =
    picked ??
    (mode === "entities" && visibleSubjects.length
      ? { type: "subject", key: visibleSubjects[0].key }
      : { type: "event", key: data.nodes[0].id });
  const node =
    selection.type === "event"
      ? data.nodes.find((row) => row.id === selection.key)
      : undefined;
  const subject =
    selection.type === "subject"
      ? subjects.find((row) => row.key === selection.key)
      : undefined;
  const edge =
    selection.type === "relationship"
      ? data.edges.find((row) => row.id === selection.key)
      : undefined;
  const supporting = node
    ? [node]
    : (subject?.events ??
      data.nodes.filter(
        (row) => row.id === edge?.source_id || row.id === edge?.target_id,
      ));
  const sources = [
    ...new Set(supporting.map(({ evidence_id }) => evidence_id)),
  ];
  return (
    <>
      <div className="graph-layout">
        {mode === "events" ? (
          <GraphCanvas
            data={data}
            subjects={subjects}
            kind={kind}
            selection={selection}
            onSelect={setPicked}
          />
        ) : (
          <div className="entity-browser" aria-label="Graph entities">
            {visibleSubjects.length ? (
              visibleSubjects.map((row) => {
                const { icon: Icon, color, name } = styleFor(row.kind);
                return (
                  <button
                    key={row.key}
                    aria-pressed={selection.key === row.key}
                    onClick={() => setPicked({ type: "subject", key: row.key })}
                  >
                    <Icon color={color} size={18} />
                    <span>
                      <small>{name}</small>
                      {row.value}
                    </span>
                    <small>{row.events.length} events</small>
                  </button>
                );
              })
            ) : (
              <Empty>
                No entities of this type are present in these results.
              </Empty>
            )}
          </div>
        )}
        <aside className="graph-detail" aria-label="Graph selection details">
          {node && (
            <>
              <small className="graph-detail-kind">
                {label(node.category)} event
              </small>
              <h3>{eventTitle(node)}</h3>
              <p>
                <Badge value={node.severity} /> {date(node.timestamp)}
                {node.timestamp ? " UTC" : ""}
              </p>
              {node.username && (
                <p>
                  Account <strong>{node.username}</strong>
                </p>
              )}
              {node.hostname && (
                <p>
                  Host <strong>{node.hostname}</strong>
                </p>
              )}
              <a href={link(id, "events", node.id)}>Inspect event</a>
            </>
          )}
          {subject && (
            <>
              <small className="graph-detail-kind">
                {styleFor(subject.kind).name}
              </small>
              <h3>{subject.value}</h3>
              {subject.kind === "finding" && (
                <a href={link(id, "findings", subject.ref)}>Inspect finding</a>
              )}
              {subject.kind === "indicator" && (
                <a href={link(id, "intelligence")}>Open indicator register</a>
              )}
            </>
          )}
          {edge && (
            <Relationship key={edge.id} id={id} edge={edge} changed={refresh} />
          )}
          <h3>Supporting evidence</h3>
          <ul className="graph-evidence-list">
            {sources.map((source) => (
              <li key={source}>
                <a href={link(id, "evidence", source)}>
                  {data.sources[source] ?? "Open original evidence"}
                </a>
              </li>
            ))}
          </ul>
          <details open={node ? undefined : true} key={selection.key}>
            <summary>
              {supporting.length} supporting{" "}
              {supporting.length === 1 ? "record" : "records"}
            </summary>
            <ul className="graph-evidence-list graph-event-references">
              {supporting.map((row) => (
                <li key={row.id}>
                  <a href={link(id, "events", row.id)}>{eventTitle(row)}</a>
                  <small>{row.source_ref}</small>
                </li>
              ))}
            </ul>
          </details>
        </aside>
      </div>
      <p className="graph-result-summary">
        {data.nodes.length} events · {data.edges.length} event relationships
        {data.limited
          ? " · Result capped. Increase the limit or narrow the filters."
          : ""}
      </p>
    </>
  );
}

export function GraphView({ id }: { id: string }) {
  const [filter, setFilter] = useState("");
  const [view, setView] = useState("events");
  const [kind, setKind] = useState("");
  const [limit, setLimit] = useState(12);
  const state = useData<Graph>(
    base(id) + "/correlation" + query({ relationship: filter, kind, limit }),
  );
  return (
    <Panel
      title="Correlation graph"
      hint="Trace events to observed entities, original evidence and inferred relationships."
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
          choices={Object.keys(kinds)
            .filter((key) => !["event", "evidence"].includes(key))
            .concat(["process", "process_id", "hash"])}
          value={kind}
          onChange={setKind}
        />
        <label className="filter">
          <span>Relationship limit</span>
          <select
            value={limit}
            onChange={(event) => setLimit(Number(event.target.value))}
          >
            {[12, 24, 48, 120].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="forensic-legend" aria-label="Graph legend">
        <ul>
          {primaryKinds.map((key) => {
            const { icon: Icon, color, name } = kinds[key];
            return (
              <li key={key}>
                <Icon size={15} color={color} /> {name}
              </li>
            );
          })}
        </ul>
        <ul>
          <li>
            <i className="legend-observed" /> Observed relationship
          </li>
          <li>
            <i className="legend-inferred" /> Inferred relationship
          </li>
          <li>
            <i className="legend-source" /> Source association
          </li>
        </ul>
      </div>
      <Load state={state}>
        {(data) =>
          data.nodes.length ? (
            <GraphResult
              key={[filter, kind, limit, view].join("/")}
              data={data}
              id={id}
              kind={kind}
              mode={view}
              refresh={state.refresh}
            />
          ) : (
            <Empty>
              No events match these graph filters. Clear filters or run case
              analysis to populate relationships.
            </Empty>
          )
        }
      </Load>
    </Panel>
  );
}
