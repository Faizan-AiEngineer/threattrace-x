import { useCallback, useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Inbox,
  LoaderCircle,
  X,
} from "lucide-react";
import { api } from "./api";
import type { Page } from "./api";

export function useData<T>(path: string | null) {
  const [state, setState] = useState<{
    path: string | null;
    data?: T;
    error?: string;
  }>({ path: null });
  const [version, setVersion] = useState(0);
  const refresh = useCallback(() => setVersion((current) => current + 1), []);
  useEffect(() => {
    if (!path) return;
    let active = true;
    api<T>(path).then(
      (data) => {
        if (active) setState({ path, data });
      },
      (error) => {
        if (active) setState({ path, error: error.message });
      },
    );
    return () => {
      active = false;
    };
  }, [path, version]);
  const current = state.path === path ? state : undefined;
  return {
    data: current?.data,
    error: current?.error,
    loading: !!path && !current,
    refresh,
  };
}
export function useAction() {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  async function run(task: () => Promise<void>, success = "") {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await task();
      setMessage(success);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }
  return { run, busy, message, error };
}
export const statuses = [
  "open",
  "under_investigation",
  "awaiting_evidence",
  "resolved",
  "closed",
  "archived",
];
export const severities = ["info", "low", "medium", "high", "critical"];
export function label(value: string) {
  return value.replaceAll("_", " ").replace(/^./, (char) => char.toUpperCase());
}
export function date(value: string | null | undefined, local = false) {
  if (!value) return "—";
  return new Intl.DateTimeFormat("en-GB", {
    month: "short",
    day: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: local ? undefined : "UTC",
    hourCycle: "h23",
  }).format(new Date(value));
}
export function bytes(number: number) {
  return number >= 1024 * 1024
    ? (number / (1024 * 1024)).toFixed(1) + " MiB"
    : number >= 1024
      ? (number / 1024).toFixed(1) + " KiB"
      : number + " B";
}
export function Badge({ value }: { value: string }) {
  return (
    <span className={"badge badge-" + value}>
      <span className="badge-dot" />
      {label(value)}
    </span>
  );
}
export function Panel({
  title,
  hint,
  action,
  children,
  className = "",
}: {
  title: string;
  hint?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={"panel " + className}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {hint && <p>{hint}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
export function Empty({
  children = "No records match this view.",
}: {
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <Inbox size={21} />
      <p>{children}</p>
    </div>
  );
}
export function Feedback({
  error,
  message,
}: {
  error?: string;
  message?: string;
}) {
  return error ? (
    <div className="feedback error" role="alert">
      <AlertTriangle size={17} />
      {error}
    </div>
  ) : message ? (
    <div className="feedback success" role="status">
      {message}
    </div>
  ) : null;
}
export function Load<T>({
  state,
  children,
}: {
  state: { loading: boolean; data?: T; error?: string };
  children: (value: T) => ReactNode;
}) {
  if (state.loading)
    return (
      <div className="empty" role="status">
        <LoaderCircle className="spin" size={20} />
        Loading records…
      </div>
    );
  if (state.error) return <Feedback error={state.error} />;
  return state.data === undefined ? null : children(state.data);
}
export function Table({
  headers,
  rows,
}: {
  headers: string[];
  rows: ReactNode[][];
}) {
  if (!rows.length) return <Empty />;
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            {headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, offset) => (
                <td key={offset}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function Pager<T>({
  data,
  go,
}: {
  data: Page<T>;
  go: (page: number) => void;
}) {
  if (data.total <= data.limit) return null;
  const pages = Math.ceil(data.total / data.limit);
  return (
    <nav className="pager" aria-label="Results pagination">
      <span>
        {data.total} records · Page {data.page} of {pages}
      </span>
      <button
        className="icon-button"
        aria-label="Previous page"
        disabled={data.page <= 1}
        onClick={() => go(data.page - 1)}
      >
        <ChevronLeft size={17} />
      </button>
      <button
        className="icon-button"
        aria-label="Next page"
        disabled={data.page >= pages}
        onClick={() => go(data.page + 1)}
      >
        <ChevronRight size={17} />
      </button>
    </nav>
  );
}
export function Modal({
  title,
  close,
  children,
}: {
  title: string;
  close: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      ref={ref}
      onCancel={(event) => {
        event.preventDefault();
        close();
      }}
      aria-label={title}
    >
      <div className="modal-heading">
        <h2>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={close}
        >
          <X size={19} />
        </button>
      </div>
      <div className="modal-body">{children}</div>
    </dialog>
  );
}
export function formData(event: FormEvent<HTMLFormElement>) {
  event.preventDefault();
  return new FormData(event.currentTarget);
}
export function Select({
  title,
  choices,
  value,
  onChange,
  all = false,
}: {
  title: string;
  choices: readonly string[];
  value: string;
  onChange: (value: string) => void;
  all?: boolean;
}) {
  return (
    <label className="filter">
      <span>{title}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {all && <option value="">All</option>}
        {choices.map((choice) => (
          <option key={choice} value={choice}>
            {label(choice)}
          </option>
        ))}
      </select>
    </label>
  );
}
export function definition(items: [string, ReactNode][]) {
  return (
    <dl className="definition">
      {items.map(([name, val]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{val ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}
