import { useState } from "react";
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Briefcase,
  ChevronRight,
  CircleAlert,
  Fingerprint,
  Plus,
  Search,
  Settings2,
} from "lucide-react";
import { api, query } from "./api";
import type { Activity as Audit, Case, Page, User } from "./api";
import {
  Badge,
  date,
  definition,
  Empty,
  Feedback,
  formData,
  Load,
  Pager,
  Panel,
  Select,
  severities,
  statuses,
  Table,
  useAction,
  useData,
} from "./ui";
import { EvidenceView, CustodyView } from "./evidence";
import { EventsView, FindingsView, NotesView } from "./events";
import {
  GraphView,
  EntitiesView,
  IntelligenceView,
  NetworkView,
  ReportsView,
} from "./analysisViews";

export const base = (id: string) => "/cases/" + id;
export const link = (id: string, tab = "", item = "") =>
  "#/cases/" + id + (tab ? "/" + tab : "") + (item ? "/" + item : "");
export function CaseList() {
  const [filters, set] = useState({
    q: "",
    status: "",
    severity: "",
    sort: "recent",
    page: 1,
  });
  const update = (key: string, value: string) =>
    set((state) => ({ ...state, [key]: value, page: 1 }));
  const state = useData<Page<Case>>("/cases" + query(filters));
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Investigations</h1>
          <p>Manage case scope, severity and evidence access.</p>
        </div>
        <a href="#/cases/new" className="button primary">
          <Plus size={17} /> New investigation
        </a>
      </div>
      <Panel title="Case register">
        <div className="toolbar">
          <label className="filter search">
            <span>Search cases</span>
            <span>
              <Search size={16} />
              <input
                value={filters.q}
                placeholder="Title or description"
                onChange={(event) => update("q", event.target.value)}
              />
            </span>
          </label>
          <Select
            title="Status"
            all
            choices={statuses}
            value={filters.status}
            onChange={(value) => update("status", value)}
          />
          <Select
            title="Severity"
            all
            choices={severities}
            value={filters.severity}
            onChange={(value) => update("severity", value)}
          />
          <Select
            title="Sort"
            choices={["recent", "oldest", "title"]}
            value={filters.sort}
            onChange={(value) => update("sort", value)}
          />
        </div>
        <Load state={state}>
          {(data) => (
            <>
              <Table
                headers={[
                  "Investigation",
                  "Status",
                  "Severity",
                  "Investigator",
                  "Last updated",
                  "Open",
                ]}
                rows={data.items.map((item) => [
                  <a className="cell-title" href={link(item.id)}>
                    {item.title}
                    <small>
                      {item.classification}
                      {item.synthetic ? " · Synthetic" : ""}
                    </small>
                  </a>,
                  <Badge value={item.status} />,
                  <Badge value={item.severity} />,
                  item.investigator,
                  date(item.updated_at),
                  <a
                    className="icon-button"
                    href={link(item.id)}
                    aria-label={"Open " + item.title}
                  >
                    <ChevronRight size={17} />
                  </a>,
                ])}
              />
              <Pager
                data={data}
                go={(page) => set((old) => ({ ...old, page }))}
              />
            </>
          )}
        </Load>
      </Panel>
    </>
  );
}
export function CaseForm({ user, existing }: { user: User; existing?: Case }) {
  const action = useAction();
  return (
    <>
      <div className="page-heading">
        <div>
          <a
            className="inline-link"
            href={existing ? link(existing.id) : "#/cases"}
          >
            <ArrowLeft size={15} /> Back
          </a>
          <h1>{existing ? "Edit investigation" : "New investigation"}</h1>
          <p>Record the case owner, classification and investigative scope.</p>
        </div>
      </div>
      <Panel title="Case details" className="narrow">
        <form
          className="form"
          onSubmit={(event) => {
            const data = formData(event);
            if (
              existing &&
              data.get("status") === "archived" &&
              existing.status !== "archived" &&
              !window.confirm(
                "Archive this investigation and record the action in custody history?",
              )
            )
              return;
            void action.run(async () => {
              const created = await api<Case>(
                existing ? base(existing.id) : "/cases",
                existing ? "PUT" : "POST",
                Object.fromEntries(data),
              );
              window.location.hash = link(created.id);
            });
          }}
        >
          <label>
            Case title
            <input
              required
              name="title"
              maxLength={160}
              defaultValue={existing?.title}
            />
          </label>
          <label>
            Scope and description
            <textarea
              name="description"
              rows={5}
              defaultValue={existing?.description}
            />
          </label>
          <div className="form-grid">
            <label>
              Investigator
              <input
                required
                name="investigator"
                defaultValue={existing?.investigator ?? user.username}
              />
            </label>
            <label>
              Classification
              <input
                required
                name="classification"
                defaultValue={existing?.classification ?? "Unclassified"}
              />
            </label>
            <label>
              Severity
              <select
                name="severity"
                defaultValue={existing?.severity ?? "medium"}
              >
                {severities.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
            <label>
              Status
              <select name="status" defaultValue={existing?.status ?? "open"}>
                {statuses.map((value) => (
                  <option key={value} value={value}>
                    {value.replaceAll("_", " ")}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <Feedback error={action.error} />
          <button className="primary" disabled={action.busy}>
            {existing ? "Save investigation" : "Create investigation"}
            <ArrowRight size={16} />
          </button>
        </form>
      </Panel>
    </>
  );
}

const tabs = [
  ["overview", "Overview"],
  ["evidence", "Evidence"],
  ["events", "Events"],
  ["timeline", "Timeline"],
  ["findings", "Findings"],
  ["entities", "Entities"],
  ["graph", "Correlation graph"],
  ["custody", "Chain of custody"],
  ["notes", "Notes"],
  ["reports", "Reports"],
  ["network", "Network"],
  ["intelligence", "Intelligence"],
] as const;

function CaseOverview({ item }: { item: Case }) {
  const audit = useData<Page<Audit>>(base(item.id) + "/activity?limit=8");
  return (
    <div className="chart-grid split">
      <Panel title="Investigation scope" hint={item.id}>
        <div className="panel-body">
          <p className="scope">
            {item.description || "No narrative scope recorded."}
          </p>
          {definition([
            ["Investigator", item.investigator],
            ["Classification", item.classification],
            ["Opened (UTC)", date(item.created_at)],
            ["Status", <Badge value={item.status} />],
            ["Severity", <Badge value={item.severity} />],
          ])}
          <div className="actions room">
            <a href={link(item.id, "evidence")} className="button">
              <Fingerprint size={16} /> Review evidence
            </a>
            <a href={link(item.id, "findings")} className="button">
              <CircleAlert size={16} /> Review findings
            </a>
          </div>
        </div>
      </Panel>
      <Panel title="Activity log" hint="Recent changes and analysis runs">
        <Load state={audit}>
          {(data) =>
            data.items.length ? (
              <div className="dense-list">
                {data.items.map((record) => (
                  <div className="dense-row" key={record.id}>
                    <span className="row-icon">
                      <Activity size={15} />
                    </span>
                    <span>
                      <strong>{record.action.replaceAll("_", " ")}</strong>
                      <small>{record.actor}</small>
                    </span>
                    <small>{date(record.timestamp)}</small>
                  </div>
                ))}
              </div>
            ) : (
              <Empty />
            )
          }
        </Load>
      </Panel>
    </div>
  );
}
export function Workspace({
  id,
  tab,
  item,
  user,
}: {
  id: string;
  tab: string;
  item?: string;
  user: User;
}) {
  const current = useData<Case>(base(id));
  const action = useAction();
  const [windowSeconds, setWindow] = useState(300);
  const [revision, setRevision] = useState(0);
  return (
    <Load state={current}>
      {(caseInfo) => {
        if (tab === "edit") return <CaseForm user={user} existing={caseInfo} />;
        const views: Record<string, React.ReactNode> = {
          overview: <CaseOverview item={caseInfo} />,
          evidence: <EvidenceView id={id} item={item} />,
          events: <EventsView id={id} item={item} />,
          timeline: <EventsView id={id} item={item} timeline />,
          findings: <FindingsView id={id} item={item} />,
          entities: <EntitiesView id={id} />,
          graph: <GraphView id={id} />,
          custody: <CustodyView id={id} item={item} />,
          notes: <NotesView id={id} />,
          reports: <ReportsView id={id} />,
          network: <NetworkView id={id} />,
          intelligence: <IntelligenceView id={id} />,
        };
        return (
          <>
            <div className="page-heading case-heading">
              <div>
                <a href="#/cases" className="inline-link">
                  <ArrowLeft size={14} /> Investigations
                </a>
                <h1>{caseInfo.title}</h1>
                <div className="heading-meta">
                  <Badge value={caseInfo.status} />
                  <Badge value={caseInfo.severity} />
                  {caseInfo.synthetic && (
                    <span className="section-chip">Synthetic</span>
                  )}
                  <span>{caseInfo.classification}</span>
                </div>
              </div>
              <div className="actions">
                <a href={link(id, "edit")} className="button">
                  <Settings2 size={16} /> Edit case
                </a>
                <form
                  className="analysis-form"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void action.run(async () => {
                      await api(base(id) + "/analyze", "POST", {
                        window: windowSeconds,
                      });
                      setRevision((value) => value + 1);
                    }, "Analysis completed. Findings and relationships are current.");
                  }}
                >
                  <label className="sr-only" htmlFor="analysis-window">
                    Correlation window in seconds
                  </label>
                  <input
                    id="analysis-window"
                    title="Correlation window in seconds"
                    type="number"
                    min={1}
                    max={86400}
                    required
                    value={windowSeconds}
                    onChange={(event) => setWindow(Number(event.target.value))}
                  />
                  <button className="primary" disabled={action.busy}>
                    <Briefcase size={16} /> Run analysis
                  </button>
                </form>
              </div>
            </div>
            <Feedback error={action.error} message={action.message} />
            <nav className="tabs" aria-label="Investigation views">
              {tabs.map(([key, name]) => (
                <a
                  key={key}
                  aria-current={tab === key ? "page" : undefined}
                  href={link(id, key)}
                >
                  {name}
                </a>
              ))}
            </nav>
            <div key={revision}>
              {views[tab] ?? <Empty>Unknown investigation view.</Empty>}
            </div>
          </>
        );
      }}
    </Load>
  );
}
