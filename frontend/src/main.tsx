import { useEffect, useState } from "react";
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
import { CaseForm, CaseList, Workspace } from "./workspace";
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
function CaseSelector({ tab, user }: { tab: string; user: User }) {
  const state = useData<Page<Case>>("/cases?limit=200");
  const choices = state.data?.items ?? [];
  const [selected, setSelected] = useState("");
  const active = choices.find((item) => item.id === selected) ?? choices[0];
  return (
    <Load state={state}>
      {() =>
        active ? (
          <>
            <div className="case-selector">
              <label>
                Investigation
                <select
                  value={active.id}
                  onChange={(event) => setSelected(event.target.value)}
                >
                  {choices.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.title}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <Workspace
              key={active.id + tab}
              id={active.id}
              tab={tab}
              user={user}
            />
          </>
        ) : (
          <Empty>
            <a href="#/cases/new">Create an investigation</a> to open this
            workspace.
          </Empty>
        )
      }
    </Load>
  );
}
function App() {
  const [route, setRoute] = useState(window.location.hash.slice(1) || "/");
  const [user, setUser] = useState<User | null | undefined>(undefined);
  const [menu, setMenu] = useState(false);
  const [sessionError, setSessionError] = useState("");
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
    window.addEventListener("hashchange", navigate);
    window.addEventListener("ttx-session-expired", expired);
    return () => {
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
  const segments = route.split("/").filter(Boolean);
  const [area, id, tab, item] = segments;
  const selected =
    nav.find(([, url]) => url === route) ??
    (area === "cases" ? nav[1] : nav[0]);
  const title = selected[0];
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
      />
    );
  else if (area === "cases") content = <CaseList />;
  else if (area === "work" && id)
    content = <CaseSelector key={route} tab={id} user={user} />;
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
      <aside className={"sidebar " + (menu ? "open" : "")}>
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
                aria-current={selected[1] === url ? "page" : undefined}
                className={selected[1] === url ? "active" : ""}
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
              onClick={() => setMenu(!menu)}
            >
              <Menu size={21} />
            </button>
            <span className="crumb-root">Workspace</span>
            <ChevronRight className="crumb-root" size={14} />
            <strong>{title}</strong>
          </div>
          <div className="account">
            <a
              className="icon-button alert-button"
              href="#/work/findings"
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
