import { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowLeft,
  BellDot,
  BookOpenCheck,
  Briefcase,
  ChevronRight,
  ClipboardList,
  Database,
  FileText,
  FlaskConical,
  GitBranch,
  LayoutDashboard,
  LogOut,
  Menu,
  Network,
  Radio,
  Settings,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { api } from "./api";
import type { Case, Page, User } from "./api";
import { Empty, Feedback, formData, Load, useAction, useData } from "./ui";
import { Overview } from "./overview";
import { CaseForm, caseTabs, CaseList, link, Workspace } from "./workspace";
import { PasswordChange } from "./access";
import { Research, RuleSettings, SettingsView } from "./operations";
import "./style.css";

const nav = [
  ["Overview", "/", LayoutDashboard],
  ["Investigations", "/cases", Briefcase],
  ["Evidence Vault", "/work/evidence", Database],
  ["Incident Timeline", "/work/timeline", Activity],
  ["Correlation Graph", "/work/graph", GitBranch],
  ["Network Forensics", "/work/network", Network],
  ["Threat Intelligence", "/work/intelligence", Radio],
  ["Detection Rules", "/rules", SlidersHorizontal],
  ["Chain of Custody", "/work/custody", ClipboardList],
  ["Reports", "/work/reports", FileText],
  ["Research Lab", "/research", FlaskConical],
  ["Settings", "/settings", Settings],
] as const;
function Brand() {
  return (
    <a className="brand" href="#/">
      <span className="brand-mark">
        <Shield size={23} />
        <span>×</span>
      </span>
      <span>
        <strong>
          ThreatTrace <b>X</b>
        </strong>
        <small>FORENSIC WORKBENCH</small>
      </span>
    </a>
  );
}
function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const action = useAction();
  return (
    <main className="login">
      <section className="login-card">
        <Brand />
        <h1>Sign in</h1>
        <p>Access the local forensic investigation workspace.</p>
        <form
          className="form"
          onSubmit={(event) => {
            const form = formData(event);
            void action.run(async () =>
              onLogin(
                await api<User>(
                  "/auth/login",
                  "POST",
                  Object.fromEntries(form),
                ),
              ),
            );
          }}
        >
          <label>
            Username
            <input
              name="username"
              autoComplete="username"
              required
              minLength={3}
              autoFocus
            />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <Feedback error={action.error} />
          <button className="primary" disabled={action.busy}>
            Sign in <ChevronRight size={17} />
          </button>
        </form>
        <small className="login-foot">
          <ShieldCheck size={15} /> Local evidence workspace
        </small>
      </section>
    </main>
  );
}
const workTitles: Record<string, string> = {
  ...Object.fromEntries(
    nav
      .filter(([, url]) => url.startsWith("/work/"))
      .map(([title, url]) => [url.split("/").at(-1), title]),
  ),
  findings: "Findings",
};

type CurrentCase = Pick<Case, "id" | "title">;

function storedCase(userId: string): CurrentCase | undefined {
  try {
    const saved = JSON.parse(
      sessionStorage.getItem("ttx-case:" + userId) ?? "null",
    );
    if (
      saved &&
      typeof saved.id === "string" &&
      typeof saved.title === "string"
    )
      return { id: saved.id, title: saved.title };
  } catch {
    // A browser can restrict session storage.
  }
}

function CaseSelector({
  tab,
  user,
  active,
  onSelect,
}: {
  tab: string;
  user: User;
  active?: CurrentCase;
  onSelect: (value: CurrentCase) => void;
}) {
  const [page, setPage] = useState(1);
  const state = useData<Page<Case>>("/cases?limit=50&sort=title&page=" + page);
  return (
    <>
      <Load state={state}>
        {(data) => (
          <div className="case-selector">
            <label htmlFor="workspace-case">Active investigation</label>
            <select
              id="workspace-case"
              value={active?.id ?? ""}
              onChange={(event) => {
                const choice = data.items.find(
                  ({ id }) => id === event.target.value,
                );
                if (choice) onSelect(choice);
              }}
            >
              <option value="" disabled>
                Choose an investigation
              </option>
              {active && !data.items.some(({ id }) => id === active.id) && (
                <option value={active.id}>{active.title}</option>
              )}
              {data.items.map(({ id, title }) => (
                <option key={id} value={id}>
                  {title}
                </option>
              ))}
            </select>
            {data.total > data.limit && (
              <div className="actions">
                <button disabled={page === 1} onClick={() => setPage(page - 1)}>
                  Previous cases
                </button>
                <button
                  disabled={page * data.limit >= data.total}
                  onClick={() => setPage(page + 1)}
                >
                  More cases
                </button>
              </div>
            )}
          </div>
        )}
      </Load>
      {active ? (
        <Workspace
          key={active.id + "/" + tab}
          id={active.id}
          tab={tab}
          user={user}
          onOpen={onSelect}
        />
      ) : (
        state.data && (
          <Empty>
            {state.data.total ? (
              "Select the investigation you want to work on."
            ) : (
              <a href="#/cases/new">Create an investigation</a>
            )}
          </Empty>
        )
      )}
    </>
  );
}
function App() {
  const [route, setRoute] = useState(window.location.hash.slice(1) || "/");
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [menu, setMenu] = useState(false);
  const [sessionError, setSessionError] = useState("");
  const [caseByUser, setCaseByUser] = useState<Record<string, CurrentCase>>({});
  const userId = user?.id;
  const onSelect = useCallback(
    ({ id, title }: CurrentCase) => {
      if (!userId) return;
      setCaseByUser((previous) => {
        const current = previous[userId];
        return current?.id === id && current.title === title
          ? previous
          : { ...previous, [userId]: { id, title } };
      });
      try {
        sessionStorage.setItem(
          "ttx-case:" + userId,
          JSON.stringify({ id, title }),
        );
      } catch {
        /* Keep the current investigation in memory. */
      }
    },
    [userId],
  );
  const auth = useAction();
  useEffect(() => {
    api<User>("/auth/me").then(setUser, (error) => {
      if (error.status !== 401) setSessionError(error.message);
      setUser(null);
    });
    const navigate = () => {
      setRoute(window.location.hash.slice(1) || "/");
      setMenu(false);
      window.scrollTo(0, 0);
    };
    const expired = () => setUser(null);
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setMenu(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    window.addEventListener("hashchange", navigate);
    window.addEventListener("ttx-session-expired", expired);
    return () => {
      window.removeEventListener("keydown", closeOnEscape);
      window.removeEventListener("hashchange", navigate);
      window.removeEventListener("ttx-session-expired", expired);
    };
  }, []);
  if (user === undefined)
    return (
      <div className="empty" role="status">
        Checking session…
      </div>
    );
  if (!user)
    return (
      <>
        <Feedback error={sessionError} />
        <Login
          onLogin={(account) => {
            setSessionError("");
            setUser(account);
          }}
        />
      </>
    );
  if (user.password_change_required)
    return (
      <main className="login">
        <section className="login-card">
          <Brand />
          <h1>Change temporary password</h1>
          <p>
            Set a new password to open the workspace. You will sign in again
            afterward.
          </p>
          <PasswordChange temporary onChanged={() => setUser(null)} />
          <button
            onClick={() =>
              void auth.run(async () => {
                await api("/auth/logout", "POST");
                setUser(null);
              })
            }
          >
            Sign out
          </button>
          <Feedback error={auth.error} />
        </section>
      </main>
    );
  const segments = route.split("/").filter(Boolean);
  const [area, id, tab, item] = segments;
  const active = caseByUser[user.id] ?? storedCase(user.id);
  const caseRoute = area === "cases" && id && id !== "new";
  const workTab = area === "work" ? id : caseRoute ? tab : undefined;
  const workPath = workTab && "/work/" + workTab;
  const selected =
    nav.find(([, url]) => url === route || url === workPath) ??
    (area === "cases" ? nav[1] : undefined);
  const title =
    area === "work"
      ? (workTitles[id] ?? "Workspace unavailable")
      : id === "new" && area === "cases"
        ? "New investigation"
        : caseRoute && tab
          ? tab === "edit"
            ? "Edit investigation"
            : (workTitles[tab] ??
              caseTabs.find(([key]) => key === tab)?.[1] ??
              "Workspace unavailable")
          : (selected?.[0] ?? "Workspace unavailable");
  const caseCrumb = caseRoute && active?.id === id && tab ? active : undefined;
  let content;
  if (area === "cases" && id === "new") content = <CaseForm user={user} />;
  else if (area === "cases" && id)
    content = (
      <Workspace
        key={route}
        id={id}
        tab={tab || "overview"}
        item={item}
        user={user}
        onOpen={onSelect}
      />
    );
  else if (area === "cases") content = <CaseList />;
  else if (area === "work" && id && workTitles[id])
    content = (
      <CaseSelector
        key={route}
        tab={id}
        user={user}
        active={active}
        onSelect={onSelect}
      />
    );
  else if (area === "rules") content = <RuleSettings user={user} />;
  else if (area === "research") content = <Research />;
  else if (area === "settings") content = <SettingsView user={user} />;
  else if (!area) content = <Overview username={user.username} />;
  else
    content = (
      <Empty>
        <a href="#/">
          <ArrowLeft size={15} /> Return to overview
        </a>
      </Empty>
    );
  return (
    <div className="app">
      <a
        className="skip"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById("main")?.focus();
        }}
      >
        Skip to content
      </a>
      {menu && (
        <button
          className="mobile-cover"
          aria-label="Close navigation"
          onClick={() => setMenu(false)}
        />
      )}
      <aside
        id="workspace-sidebar"
        className={"sidebar " + (menu ? "open" : "")}
      >
        <Brand />
        <nav aria-label="Primary navigation">
          <div className="nav-caption">WORKSPACE</div>
          {nav.map(([name, url, Icon], index) => (
            <div key={url}>
              {index === 10 && (
                <div className="nav-caption second">PLATFORM</div>
              )}
              <a
                href={"#" + url}
                onClick={() => setMenu(false)}
                aria-current={selected?.[1] === url ? "page" : undefined}
                className={selected?.[1] === url ? "active" : ""}
              >
                <Icon size={17} />
                <span>{name}</span>
              </a>
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="online-dot" /> Local workspace{" "}
          <BookOpenCheck size={15} />
        </div>
      </aside>
      <div className="shell">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-menu"
              aria-label="Open navigation"
              aria-expanded={menu}
              aria-controls="workspace-sidebar"
              onClick={() => setMenu(!menu)}
            >
              <Menu size={21} />
            </button>
            <nav className="breadcrumb-trail" aria-label="Breadcrumb">
              {area === "cases" && id ? (
                <a href="#/cases" className="crumb-root">
                  Investigations
                </a>
              ) : (
                <span className="crumb-root">Workspace</span>
              )}
              <ChevronRight
                className="crumb-root"
                size={14}
                aria-hidden="true"
              />
              {caseCrumb && (
                <>
                  <a className="crumb-case" href={link(caseCrumb.id)}>
                    {caseCrumb.title}
                  </a>
                  <ChevronRight
                    className="crumb-case"
                    size={14}
                    aria-hidden="true"
                  />
                </>
              )}
              <strong aria-current="page">
                {caseRoute && !tab && active?.id === id ? active.title : title}
              </strong>
            </nav>
          </div>
          <div className="account">
            <a
              className="icon-button alert-button"
              href={caseRoute ? link(id, "findings") : "#/work/findings"}
              aria-label="Open findings"
            >
              <BellDot size={18} />
            </a>
            <span className="avatar">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <span className="account-text">
              <strong>{user.username}</strong>
              <small>{user.role}</small>
            </span>
            <button
              className="icon-button"
              title="Sign out"
              aria-label="Sign out"
              onClick={() =>
                void auth.run(async () => {
                  await api("/auth/logout", "POST");
                  setUser(null);
                })
              }
            >
              <LogOut size={16} />
            </button>
          </div>
        </header>
        <main id="main" className="content" tabIndex={-1}>
          <Feedback error={auth.error} />
          {content}
        </main>
      </div>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
