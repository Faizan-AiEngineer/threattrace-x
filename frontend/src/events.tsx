import { useState } from "react";
import { ArrowLeft, Clock, Download, Minus, Plus } from "lucide-react";
import { api, download, query } from "./api";
import type { Event, Evidence, Finding, Note, Page } from "./api";
import { base, link } from "./workspace";
import {
  Badge,
  date,
  definition,
  Empty,
  Feedback,
  formData,
  label,
  Load,
  Pager,
  Panel,
  Select,
  severities,
  Table,
  useAction,
  useData,
} from "./ui";

function NoteForm({
  id,
  item,
  changed,
}: {
  id: string;
  item?: string;
  changed: () => void;
}) {
  const action = useAction();
  return (
    <form
      className="form"
      onSubmit={(event) => {
        const form = event.currentTarget;
        const data = formData(event);
        void action.run(async () => {
          await api(base(id) + "/notes", "POST", {
            body: data.get("body"),
            event_id: item ?? null,
          });
          form.reset();
          changed();
        }, "Note saved.");
      }}
    >
      <label>
        {item ? "Event annotation" : "Investigator note"}
        <textarea name="body" required rows={3} maxLength={4000} />
      </label>
      <Feedback error={action.error} message={action.message} />
      <button className="primary" disabled={action.busy}>
        Add note
      </button>
    </form>
  );
}
export function NotesView({ id }: { id: string }) {
  const [page, setPage] = useState(1);
  const state = useData<Page<Note>>(base(id) + "/notes" + query({ page }));
  return (
    <div className="chart-grid split">
      <Panel title="Investigator notes">
        <Load state={state}>
          {(data) => (
            <>
              <Table
                headers={["Note", "Actor", "Time (UTC)", "Event"]}
                rows={data.items.map((row) => [
                  row.body,
                  row.actor,
                  date(row.timestamp),
                  row.event_id ? (
                    <a href={link(id, "events", row.event_id)}>Source event</a>
                  ) : (
                    "—"
                  ),
                ])}
              />
              <Pager data={data} go={setPage} />
            </>
          )}
        </Load>
      </Panel>
      <Panel title="Add a note">
        <div className="panel-body">
          <NoteForm id={id} changed={state.refresh} />
        </div>
      </Panel>
    </div>
  );
}
function EventDetail({
  id,
  item,
  timeline,
}: {
  id: string;
  item: string;
  timeline?: boolean;
}) {
  const state = useData<Event>(base(id) + "/events/" + item);
  return (
    <Load state={state}>
      {(row) => (
        <>
          <a
            className="inline-link back"
            href={link(id, timeline ? "timeline" : "events")}
          >
            <ArrowLeft size={15} /> Return to {timeline ? "timeline" : "events"}
          </a>
          <div className="chart-grid split">
            <Panel
              title={label(row.action)}
              hint={"Source record " + row.source_ref}
              action={<Badge value={row.severity} />}
            >
              <div className="panel-body">
                {definition([
                  ["Timestamp (UTC)", date(row.timestamp)],
                  ["Original timestamp", row.original_timestamp],
                  ["Time quality", label(row.time_quality)],
                  ["Clock correction", row.clock_offset + " s"],
                  ["Host", row.hostname],
                  ["Account", row.username],
                  ["Source IP", row.source_ip],
                  ["Destination IP", row.destination_ip],
                  [
                    "Evidence",
                    <a href={link(id, "evidence", row.evidence_id)}>
                      {row.evidence_id}
                    </a>,
                  ],
                ])}
                <details className="room">
                  <summary>Original record metadata</summary>
                  <pre>{JSON.stringify(row.metadata, null, 2)}</pre>
                </details>
              </div>
            </Panel>
            <Panel
              title="Related events"
              hint="Review the supporting attributes and linked source records"
            >
              {(row.relationships ?? []).length ? (
                <div className="dense-list">
                  {row.relationships?.map((edge) => {
                    const twin =
                      edge.source_id === item ? edge.target_id : edge.source_id;
                    return (
                      <a
                        className="dense-row"
                        key={edge.id}
                        href={link(id, "events", twin)}
                      >
                        <Clock size={16} />
                        <span>
                          <strong>{label(edge.kind)} relationship</strong>
                          <small>
                            {edge.attributes
                              .map((value) => value.kind)
                              .join(", ")}{" "}
                            · {Math.round(edge.confidence * 100)}% score
                          </small>
                        </span>
                        <Badge value={edge.review} />
                      </a>
                    );
                  })}
                </div>
              ) : (
                <Empty>No related events have been recorded.</Empty>
              )}
            </Panel>
          </div>
          {!!row.findings?.length && (
            <Panel title="Related findings">
              <div className="dense-list">
                {row.findings.map((finding) => (
                  <a
                    key={finding.id}
                    href={link(id, "findings", finding.id)}
                    className="dense-row"
                  >
                    <Clock size={15} />
                    <span>{finding.name}</span>
                  </a>
                ))}
              </div>
            </Panel>
          )}
          <Panel title="Event annotations">
            <div className="panel-body">
              {(row.notes ?? []).map((note) => (
                <p key={note.id}>
                  <strong>{note.actor}</strong> · {date(note.timestamp)}
                  <br />
                  {note.body}
                </p>
              ))}
              <NoteForm id={id} item={item} changed={state.refresh} />
            </div>
          </Panel>
        </>
      )}
    </Load>
  );
}
type Extent = {
  start: string | null;
  end: string | null;
  dated: number;
  undated: number;
};
function utcInput(value: string) {
  return value ? value + "Z" : "";
}
function utcField(value: number) {
  return new Date(value).toISOString().slice(0, 19);
}

function TimelineBands({
  events,
  id,
  start,
  end,
}: {
  events: Event[];
  id: string;
  start: string;
  end: string;
}) {
  const timed = events.flatMap((event) =>
    event.timestamp ? [{ event, time: Date.parse(event.timestamp) }] : [],
  );
  if (!timed.length) return null;
  const first = start ? Date.parse(utcInput(start)) : timed[0].time;
  const last = end ? Date.parse(utcInput(end)) : timed[timed.length - 1].time;
  const width = Math.max(1000, last - first);
  const categories = [...new Set(timed.map(({ event }) => event.category))];
  return (
    <div className="timeline-bands" aria-label="Event time distribution">
      <div className="timeline-bands-heading">
        <strong>Time distribution</strong>
        <small>Dated events on this page</small>
      </div>
      {categories.map((category) => (
        <div className="timeline-band" key={category}>
          <span>{label(category)}</span>
          <div>
            {timed
              .filter(({ event }) => event.category === category)
              .map(({ event, time }, index) => (
                <a
                  key={event.id}
                  href={link(id, "timeline", event.id)}
                  style={{
                    left: 8 + (84 * (time - first)) / width + "%",
                    top: 4 + (index % 3) * 6,
                  }}
                  title={
                    label(event.action) + " · " + date(event.timestamp) + " UTC"
                  }
                  aria-label={label(event.action) + " on timeline"}
                >
                  <span className={"time-point point-" + event.severity} />
                </a>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}
export function EventsView({
  id,
  item,
  timeline,
}: {
  id: string;
  item?: string;
  timeline?: boolean;
}) {
  const [filters, set] = useState({
    page: 1,
    q: "",
    category: "",
    severity: "",
    host: "",
    account: "",
    evidence_id: "",
    start: "",
    end: "",
  });
  const [local, setLocal] = useState(false);
  const extent = useData<Extent>(
    timeline && !item ? base(id) + "/timeline/extent" : null,
  );
  function zoom(factor: number) {
    if (!extent.data?.start || !extent.data.end) return;
    const min = Date.parse(extent.data.start);
    const max = Date.parse(extent.data.end);
    const start = filters.start ? Date.parse(utcInput(filters.start)) : min;
    const end = filters.end ? Date.parse(utcInput(filters.end)) : max;
    const span = factor * (end - start);
    if (!Number.isFinite(span) || span <= 1000) return;
    if (span >= max - min) {
      set((state) => ({ ...state, start: "", end: "", page: 1 }));
      return;
    }
    const center = (start + end) / 2;
    const from = Math.max(min, Math.min(max - span, center - span / 2));
    set((state) => ({
      ...state,
      start: utcField(from),
      end: utcField(Math.ceil((from + span) / 1000) * 1000),
      page: 1,
    }));
  }
  const action = useAction();
  const update = (key: string, value: string) =>
    set((state) => ({ ...state, [key]: value, page: 1 }));
  const evidence = useData<Page<Evidence>>(
    item ? null : base(id) + "/evidence?limit=200",
  );
  const state = useData<Page<Event>>(
    item
      ? null
      : base(id) +
          (timeline ? "/timeline" : "/events") +
          query({
            ...filters,
            start: utcInput(filters.start),
            end: utcInput(filters.end),
          }),
  );
  if (item) return <EventDetail id={id} item={item} timeline={timeline} />;
  return (
    <Panel
      title={timeline ? "Incident timeline" : "Normalized events"}
      hint={
        timeline
          ? "UTC ordering · uncertain timestamps appear after dated events"
          : "Each event links to its original evidence and record reference"
      }
      action={
        timeline && (
          <button
            disabled={action.busy}
            onClick={() =>
              void action.run(() =>
                download(base(id) + "/reports/events.csv", "timeline.csv"),
              )
            }
          >
            <Download size={16} /> Export timeline
          </button>
        )
      }
    >
      <div className="toolbar">
        <label className="filter">
          <span>Search</span>
          <input
            value={filters.q}
            onChange={(event) => update("q", event.target.value)}
            placeholder="Action or record ref"
          />
        </label>
        <Select
          title="Category"
          all
          choices={[
            "authentication",
            "account",
            "network",
            "process",
            "service",
            "file",
            "system",
            "web",
            "other",
          ]}
          value={filters.category}
          onChange={(value) => update("category", value)}
        />
        <Select
          title="Severity"
          all
          choices={severities}
          value={filters.severity}
          onChange={(value) => update("severity", value)}
        />
        <label className="filter">
          <span>Evidence</span>
          <select
            value={filters.evidence_id}
            onChange={(event) => update("evidence_id", event.target.value)}
          >
            <option value="">All sources</option>
            {evidence.data?.items.map((row) => (
              <option key={row.id} value={row.id}>
                {row.filename}
              </option>
            ))}
          </select>
        </label>
        <label className="filter">
          <span>Host</span>
          <input
            value={filters.host}
            onChange={(event) => update("host", event.target.value)}
            placeholder="Exact hostname"
          />
        </label>
        <label className="filter">
          <span>Account</span>
          <input
            value={filters.account}
            onChange={(event) => update("account", event.target.value)}
            placeholder="Exact username"
          />
        </label>
        {timeline && (
          <>
            <label className="filter">
              <span>From (UTC)</span>
              <input
                type="datetime-local"
                step={1}
                value={filters.start}
                onChange={(event) => update("start", event.target.value)}
              />
            </label>
            <label className="filter">
              <span>Through (UTC)</span>
              <input
                type="datetime-local"
                step={1}
                value={filters.end}
                onChange={(event) => update("end", event.target.value)}
              />
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={local}
                onChange={(event) => setLocal(event.target.checked)}
              />{" "}
              Show local time
            </label>
            <div className="actions">
              <button
                className="icon-button"
                aria-label="Zoom in timeline"
                disabled={!extent.data?.start}
                onClick={() => zoom(0.5)}
              >
                <Plus size={16} />
              </button>
              <button
                className="icon-button"
                aria-label="Zoom out timeline"
                disabled={!filters.start && !filters.end}
                onClick={() => zoom(2)}
              >
                <Minus size={16} />
              </button>
              <button
                disabled={!filters.start && !filters.end}
                onClick={() =>
                  set((state) => ({ ...state, start: "", end: "", page: 1 }))
                }
              >
                Reset time range
              </button>
            </div>
          </>
        )}
      </div>
      <Feedback error={action.error} />
      <Load state={state}>
        {(data) => (
          <>
            {timeline && (
              <TimelineBands
                events={data.items}
                id={id}
                start={filters.start}
                end={filters.end}
              />
            )}
            <Table
              headers={[
                local ? "Time (local)" : "Time (UTC)",
                "Event",
                "Host and account",
                "Severity",
                "Source reference",
              ]}
              rows={data.items.map((row) => [
                <span className={timeline ? "timeline-stamp" : ""}>
                  {row.timestamp
                    ? date(row.timestamp, local)
                    : label(row.time_quality)}
                  {row.clock_offset !== 0 && (
                    <small>Corrected {row.clock_offset} s</small>
                  )}
                </span>,
                <a
                  className="cell-title"
                  href={link(id, timeline ? "timeline" : "events", row.id)}
                >
                  {label(row.action)}
                  <small>{label(row.category)}</small>
                </a>,
                <span>
                  {row.hostname || "—"}
                  <small>{row.username || "—"}</small>
                </span>,
                <Badge value={row.severity} />,
                <a href={link(id, "evidence", row.evidence_id)}>
                  <code>{row.source_ref}</code>
                </a>,
              ])}
            />
            <Pager data={data} go={(page) => set({ ...filters, page })} />
          </>
        )}
      </Load>
    </Panel>
  );
}
function confidenceContributions(
  components: Finding["confidence"]["components"],
) {
  const availableWeight = Object.values(components).reduce(
    (total, part) => total + (part.value === null ? 0 : part.weight),
    0,
  );
  return Object.entries(components).map(
    ([name, part]) =>
      [
        name,
        part,
        availableWeight && part.contribution !== null
          ? ((100 * part.contribution) / availableWeight).toFixed(1)
          : "—",
      ] as const,
  );
}
function FindingDetail({ id, item }: { id: string; item: string }) {
  const path = base(id) + "/findings/" + item;
  const state = useData<Finding>(path);
  const action = useAction();
  return (
    <Load state={state}>
      {(row) => (
        <>
          <a className="inline-link back" href={link(id, "findings")}>
            <ArrowLeft size={15} /> Finding register
          </a>
          <div className="chart-grid split">
            <Panel
              title={row.name}
              hint={row.rule_id + " · rule v" + row.version}
              action={<Badge value={row.severity} />}
            >
              <div className="panel-body">
                <div className="actions">
                  <Badge value={row.stage} />
                  {row.technique && (
                    <a
                      href={
                        "https://attack.mitre.org/techniques/" +
                        row.technique +
                        "/"
                      }
                      target="_blank"
                      rel="noreferrer"
                    >
                      {row.technique} · rule association
                    </a>
                  )}
                </div>
                <p>{row.explanation}</p>
                <h3>Defensive next steps</h3>
                <p>{row.steps}</p>
                <h3>Limitations</h3>
                <p>{row.limitations}</p>
                <h3>Supporting events</h3>
                <ul>
                  {row.event_ids.map((event, index) => (
                    <li key={event}>
                      <a href={link(id, "events", event)}>
                        Event {index + 1} · {event.slice(0, 8)}
                      </a>
                    </li>
                  ))}
                </ul>
                <h3>Evidence references</h3>
                <ul>
                  {row.evidence_ids.map((evidence) => (
                    <li key={evidence}>
                      <a href={link(id, "evidence", evidence)}>{evidence}</a>
                    </li>
                  ))}
                </ul>
              </div>
            </Panel>
            <Panel
              title="Confidence assessment"
              hint="Weighted evidence quality and corroboration"
            >
              <div className="panel-body">
                <div className="confidence-score">
                  {row.override ?? row.confidence.score ?? "—"}{" "}
                  <small>
                    {row.override !== null
                      ? "Analyst override"
                      : label(row.confidence.category)}
                  </small>
                </div>
                {definition(
                  confidenceContributions(row.confidence.components).map(
                    ([name, part, points]) => [
                      label(name),
                      part.value === null
                        ? "Unavailable"
                        : Math.round(100 * part.value) +
                          "% value · " +
                          Math.round(100 * part.weight) +
                          "% weight · " +
                          points +
                          " score points",
                    ],
                  ),
                )}
                <form
                  className="form room"
                  onSubmit={(event) => {
                    const data = formData(event);
                    void action.run(async () => {
                      await api(path, "PATCH", {
                        stage: data.get("stage"),
                        reason: data.get("reason"),
                        override: data.get("override")
                          ? Number(data.get("override"))
                          : null,
                      });
                      state.refresh();
                    }, "Finding review saved.");
                  }}
                >
                  <label>
                    Assessment
                    <select name="stage" defaultValue={row.stage}>
                      {[
                        "observation",
                        "suspicious",
                        "confirmed",
                        "dismissed",
                      ].map((stage) => (
                        <option key={stage} value={stage}>
                          {label(stage)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Confidence override (0–100)
                    <input
                      type="number"
                      min={0}
                      max={100}
                      name="override"
                      defaultValue={row.override ?? ""}
                    />
                  </label>
                  <label>
                    Review reasoning
                    <textarea
                      name="reason"
                      rows={3}
                      required
                      defaultValue={row.review_reason}
                    />
                  </label>
                  <Feedback error={action.error} message={action.message} />
                  <button className="primary" disabled={action.busy}>
                    Save review
                  </button>
                </form>
              </div>
            </Panel>
          </div>
        </>
      )}
    </Load>
  );
}
export function FindingsView({ id, item }: { id: string; item?: string }) {
  const [filters, set] = useState({ page: 1, q: "", history: "false" });
  const state = useData<Page<Finding>>(
    item ? null : base(id) + "/findings" + query(filters),
  );
  if (item) return <FindingDetail id={id} item={item} />;
  return (
    <Panel
      title="Findings"
      hint="Rule observations and investigator assessments"
    >
      <div className="toolbar">
        <label className="filter">
          <span>Search findings</span>
          <input
            value={filters.q}
            onChange={(event) =>
              set({ ...filters, q: event.target.value, page: 1 })
            }
          />
        </label>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={filters.history === "true"}
            onChange={(event) =>
              set({
                ...filters,
                history: String(event.target.checked),
                page: 1,
              })
            }
          />{" "}
          Include previous findings
        </label>
      </div>
      <Load state={state}>
        {(data) => (
          <>
            <Table
              headers={[
                "Finding",
                "Severity",
                "Assessment",
                "Confidence",
                "Evidence",
              ]}
              rows={data.items.map((row) => [
                <a className="cell-title" href={link(id, "findings", row.id)}>
                  {row.name}
                  <small>
                    {row.rule_id} · v{row.version}
                  </small>
                </a>,
                <Badge value={row.severity} />,
                <Badge value={row.stage} />,
                row.override ?? row.confidence.score ?? "—",
                row.evidence_ids.length,
              ])}
            />
            <Pager data={data} go={(page) => set({ ...filters, page })} />
          </>
        )}
      </Load>
    </Panel>
  );
}
