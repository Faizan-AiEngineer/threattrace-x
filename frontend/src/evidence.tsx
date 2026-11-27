import { useState } from "react";
import {
  ArrowLeft,
  Copy,
  Download,
  Fingerprint,
  Plus,
  ShieldCheck,
} from "lucide-react";
import { api, download, query } from "./api";
import type { Custody, Evidence, Page } from "./api";
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

const formats = [
  "json",
  "jsonl",
  "csv",
  "syslog",
  "auth",
  "access",
  "zeek",
  "pcap",
  "windows",
];
function Upload({
  id,
  close,
  uploaded,
}: {
  id: string;
  close: () => void;
  uploaded: () => void;
}) {
  const action = useAction();
  return (
    <Modal title="Import evidence" close={close}>
      <form
        className="form"
        onSubmit={(event) => {
          const data = formData(event);
          if (!data.get("collection_at")) data.delete("collection_at");
          void action.run(async () => {
            await api(base(id) + "/evidence", "POST", data);
            uploaded();
            close();
          });
        }}
      >
        <label>
          Evidence file
          <input required type="file" name="file" />
        </label>
        <label>
          Format
          <select name="format">
            {formats.map((value) => (
              <option key={value} value={value}>
                {value.toUpperCase()}
              </option>
            ))}
          </select>
        </label>
        <label>
          Source description
          <textarea
            name="source"
            required
            maxLength={4000}
            rows={3}
            placeholder="Collection system and context"
          />
        </label>
        <label>
          Collection timestamp
          <input name="collection_at" placeholder="2025-04-08T14:00:00Z" />
        </label>
        <div className="form-grid">
          <label>
            Source timezone offset (min)
            <input
              type="number"
              name="timezone_offset"
              min={-840}
              max={840}
              defaultValue={0}
            />
          </label>
          <label>
            Clock correction (s)
            <input
              type="number"
              name="clock_offset"
              min={-86400}
              max={86400}
              defaultValue={0}
            />
          </label>
        </div>
        <Feedback error={action.error} />
        <button className="primary" disabled={action.busy}>
          <Plus size={16} /> Preserve and parse
        </button>
      </form>
    </Modal>
  );
}
function EvidenceDetail({ id, item }: { id: string; item: string }) {
  const path = base(id) + "/evidence/" + item;
  const state = useData<Evidence>(path);
  const action = useAction();
  const copy = useAction();
  const [verification, setVerification] = useState<{
    status: string;
    expected_hash: string;
    actual_hash: string | null;
  }>();
  return (
    <Load state={state}>
      {(data) => (
        <>
          <a className="inline-link back" href={link(id, "evidence")}>
            <ArrowLeft size={15} /> Evidence register
          </a>
          <div className="chart-grid split">
            <Panel
              title={data.filename}
              hint="Preserved source evidence"
              action={<Badge value={data.integrity} />}
            >
              <div className="panel-body">
                <div className="evidence-hash">
                  <span>Recorded SHA-256</span>
                  <code>{data.sha256}</code>
                  <button
                    onClick={() =>
                      void copy.run(
                        () => navigator.clipboard.writeText(data.sha256),
                        "SHA-256 copied.",
                      )
                    }
                  >
                    <Copy size={15} /> Copy SHA-256
                  </button>
                </div>
                <Feedback error={copy.error} message={copy.message} />
                {definition([
                  ["Evidence ID", data.id],
                  ["Format", data.format.toUpperCase()],
                  ["Size", bytes(data.size)],
                  ["Source", data.source],
                  ["Custodian", data.custodian],
                  ["Collected (UTC)", date(data.collection_at)],
                  ["Imported (UTC)", date(data.imported_at)],
                ])}
                <div className="actions room">
                  <button
                    className="primary"
                    disabled={action.busy}
                    onClick={() =>
                      void action.run(async () => {
                        setVerification(await api(path + "/verify", "POST"));
                        state.refresh();
                      })
                    }
                  >
                    <ShieldCheck size={16} /> Verify SHA-256
                  </button>
                  <button
                    onClick={() =>
                      void action.run(() =>
                        download(path + "/download", data.filename),
                      )
                    }
                  >
                    <Download size={16} /> Download original
                  </button>
                  <a className="button" href={link(id, "custody", data.id)}>
                    Custody history
                  </a>
                </div>
                <Feedback
                  error={action.error}
                  message={
                    verification?.status === "verified"
                      ? "Integrity verified. Preserved bytes match the recorded SHA-256."
                      : undefined
                  }
                />
                {verification?.status === "failed" && (
                  <Feedback
                    error={
                      "Integrity failed. Recorded " +
                      verification.expected_hash +
                      " · observed " +
                      (verification.actual_hash ?? "unavailable")
                    }
                  />
                )}
              </div>
            </Panel>
            <Panel
              title="Processing summary"
              hint={"Parser " + data.parser_version}
            >
              <div className="panel-body">
                {definition([
                  ["State", <Badge value={data.state} />],
                  ["Parsed events", data.stats.parsed],
                  ["Malformed records", data.stats.malformed],
                  ["Missing or uncertain time", data.stats.uncertain ?? 0],
                  ["Clock correction", data.clock_offset + " s"],
                  ["Assumed zone offset", data.timezone_offset + " min"],
                ])}
                {data.stats.errors.length > 0 && (
                  <details className="room">
                    <summary>Parser errors</summary>
                    <ul>
                      {data.stats.errors.map((error, index) => (
                        <li key={index}>
                          {error.source_ref} · {error.reason}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            </Panel>
          </div>
          <Panel title="Verification history">
            <Table
              headers={["Checked (UTC)", "Actor", "Result", "Computed SHA-256"]}
              rows={(data.verifications ?? []).map((row) => [
                date(row.timestamp),
                row.actor,
                <Badge value={row.status} />,
                <code>{row.actual_hash || "—"}</code>,
              ])}
            />
          </Panel>
        </>
      )}
    </Load>
  );
}
export function EvidenceView({ id, item }: { id: string; item?: string }) {
  const [filters, set] = useState({ page: 1, q: "", integrity: "" });
  const [upload, setUpload] = useState(false);
  const state = useData<Page<Evidence>>(
    item ? null : base(id) + "/evidence" + query(filters),
  );
  if (item) return <EvidenceDetail id={id} item={item} />;
  return (
    <Panel
      title="Evidence vault"
      hint="Original bytes, source provenance and verification status"
      action={
        <button className="primary" onClick={() => setUpload(true)}>
          <Plus size={16} /> Import evidence
        </button>
      }
    >
      {upload && (
        <Upload
          id={id}
          close={() => setUpload(false)}
          uploaded={state.refresh}
        />
      )}
      <div className="toolbar">
        <label className="filter">
          <span>Search evidence</span>
          <input
            value={filters.q}
            placeholder="Filename or SHA-256"
            onChange={(event) =>
              set({ ...filters, q: event.target.value, page: 1 })
            }
          />
        </label>
        <Select
          title="Integrity"
          choices={["verified", "unverified", "failed"]}
          all
          value={filters.integrity}
          onChange={(integrity) => set({ ...filters, integrity, page: 1 })}
        />
      </div>
      <Load state={state}>
        {(data) => (
          <>
            <Table
              headers={[
                "Evidence",
                "Format",
                "Size",
                "Integrity",
                "Processing",
                "Events",
              ]}
              rows={data.items.map((row) => [
                <a href={link(id, "evidence", row.id)} className="cell-title">
                  <span className="with-icon">
                    <Fingerprint size={15} />
                    {row.filename}
                  </span>
                  <small>{row.source}</small>
                </a>,
                row.format.toUpperCase(),
                bytes(row.size),
                <Badge value={row.integrity} />,
                <Badge value={row.state} />,
                row.stats.parsed,
              ])}
            />
            <Pager data={data} go={(page) => set({ ...filters, page })} />
          </>
        )}
      </Load>
    </Panel>
  );
}
function CustodyDetail({ id, item }: { id: string; item: string }) {
  const path = base(id) + "/evidence/" + item + "/custody";
  const [page, setPage] = useState(1);
  const [transfer, setTransfer] = useState(false);
  const state = useData<Custody>(path + query({ page }));
  const action = useAction();
  return (
    <>
      <div className="actions room">
        <a className="button" href={link(id, "evidence", item)}>
          Evidence detail
        </a>
        <button onClick={state.refresh}>
          <ShieldCheck size={17} /> Verify custody chain
        </button>
        <button onClick={() => setTransfer(true)}>Transfer custody</button>
      </div>
      {transfer && (
        <Modal title="Transfer custody" close={() => setTransfer(false)}>
          <form
            className="form"
            onSubmit={(event) => {
              const data = formData(event);
              void action.run(async () => {
                await api(path, "POST", Object.fromEntries(data));
                state.refresh();
                setTransfer(false);
              });
            }}
          >
            <label>
              Recipient username
              <input name="recipient" required />
            </label>
            <label>
              Reason
              <textarea name="reason" required rows={3} />
            </label>
            <Feedback error={action.error} />
            <button className="primary" disabled={action.busy}>
              Confirm transfer
            </button>
          </form>
        </Modal>
      )}
      <Load state={state}>
        {(value) => (
          <>
            <Feedback
              error={
                value.verification.valid
                  ? undefined
                  : (value.verification.reason ?? "Chain failed")
              }
              message={
                value.verification.valid
                  ? "Custody chain verified · " +
                    value.verification.records +
                    " records"
                  : undefined
              }
            />
            <Table
              mobileCards
              empty="No custody records exist for this evidence item."
              headers={[
                "Sequence",
                "Action",
                "Actor",
                "Time (UTC)",
                "Reason",
                "Record hash",
              ]}
              rows={value.items.map((row) => [
                <span className="custody-sequence">{row.sequence}</span>,
                <strong>{label(row.action)}</strong>,
                row.actor,
                date(row.timestamp),
                row.reason,
                <details>
                  <summary>
                    <code>{row.record_hash.slice(0, 12)}…</code>
                  </summary>
                  <code className="custody-hash">{row.record_hash}</code>
                  <p>Previous</p>
                  <code className="custody-hash">
                    {row.previous_hash ?? "—"}
                  </code>
                </details>,
              ])}
            />
            <Pager data={value} go={setPage} />
          </>
        )}
      </Load>
    </>
  );
}
export function CustodyView({ id, item }: { id: string; item?: string }) {
  const [selected, setSelected] = useState(item || "");
  const evidence = useData<Page<Evidence>>(base(id) + "/evidence?limit=200");
  const items = evidence.data?.items ?? [];
  const active = selected || items[0]?.id;
  return (
    <Panel
      title="Chain of custody"
      hint="Verify the hash-linked history of an original evidence item."
    >
      <Load state={evidence}>
        {() =>
          active ? (
            <>
              <div className="toolbar">
                <label className="filter">
                  <span>Evidence item</span>
                  <select
                    value={active}
                    onChange={(event) => setSelected(event.target.value)}
                  >
                    {items.map((e) => (
                      <option key={e.id} value={e.id}>
                        {e.filename}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="panel-body">
                <CustodyDetail key={active} id={id} item={active} />
              </div>
            </>
          ) : (
            <Empty>Import an evidence item to see its custody chain.</Empty>
          )
        }
      </Load>
    </Panel>
  );
}
