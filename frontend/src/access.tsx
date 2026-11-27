import { useState } from "react";
import { KeyRound, LockKeyhole, UserPlus } from "lucide-react";
import { api, query } from "./api";
import type { Activity, Case, Page, User } from "./api";
import {
  Badge,
  date,
  Empty,
  Feedback,
  formData,
  label,
  Load,
  Modal,
  Pager,
  Panel,
  Table,
  useAction,
  useData,
} from "./ui";

type Grant = {
  id: string;
  user_id: string;
  username: string;
  role: User["role"];
  disabled_at: string | null;
  created_at: string | null;
};
type Grants = Page<Grant> & { owner: User };
const accessActions: Record<string, string> = {
  case_access_put: "Case access granted",
  case_access_delete: "Case access revoked",
};

export function PasswordChange({
  onChanged,
  temporary = false,
}: {
  onChanged: () => void;
  temporary?: boolean;
}) {
  const action = useAction();
  return (
    <form
      className="form"
      onSubmit={(event) => {
        const data = formData(event);
        if (data.get("new_password") !== data.get("confirm")) {
          void action.run(async () => {
            throw new Error("The new passwords do not match.");
          });
          return;
        }
        void action.run(async () => {
          await api("/auth/password", "POST", {
            current_password: data.get("current_password"),
            new_password: data.get("new_password"),
          });
          onChanged();
        });
      }}
    >
      <label>
        {temporary ? "Temporary password" : "Current password"}
        <input
          type="password"
          name="current_password"
          autoComplete="current-password"
          required
        />
      </label>
      <label>
        New password
        <input
          type="password"
          name="new_password"
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
          required
        />
      </label>
      <label>
        Confirm new password
        <input
          type="password"
          name="confirm"
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
          required
        />
      </label>
      <Feedback error={action.error} />
      <button className="primary" disabled={action.busy}>
        <KeyRound size={16} /> Save new password
      </button>
    </form>
  );
}

function ManageAccount({
  target,
  mode,
  close,
  onDone,
}: {
  target: User;
  mode: "status" | "password";
  close: () => void;
  onDone: (message: string) => void;
}) {
  const action = useAction();
  const reset = mode === "password";
  const verb = target.disabled_at ? "Enable" : "Disable";
  return (
    <Modal title={reset ? "Reset password" : verb + " account"} close={close}>
      <p>
        <strong>{target.username}</strong> · {label(target.role)}
      </p>
      <p>
        {reset
          ? "Existing sessions will end. The user must replace the temporary password before opening a workspace."
          : target.disabled_at
            ? "The user can sign in again with their current credentials. Existing case grants will apply."
            : "Sign-in and active sessions will be blocked. The account and its case records will be retained."}
      </p>
      <form
        className="form"
        onSubmit={(event) => {
          const data = formData(event);
          const path = "/users/" + target.id;
          const administrator_password = data.get("administrator_password");
          void action.run(async () => {
            if (reset) {
              await api(path + "/password", "POST", {
                administrator_password,
                temporary_password: data.get("temporary_password"),
              });
            } else {
              await api(path + "/status", "PATCH", {
                administrator_password,
                disabled: !target.disabled_at,
              });
            }
            onDone(
              reset
                ? "Password reset and sessions revoked."
                : "Account " + verb.toLowerCase() + "d.",
            );
          });
        }}
      >
        {reset && (
          <label>
            Replacement temporary password
            <input
              type="password"
              name="temporary_password"
              minLength={12}
              maxLength={256}
              autoComplete="new-password"
              required
            />
          </label>
        )}
        <label>
          Your administrator password
          <input
            type="password"
            name="administrator_password"
            maxLength={256}
            autoComplete="current-password"
            required
          />
        </label>
        <Feedback error={action.error} />
        <button className="primary" disabled={action.busy}>
          {reset ? "Confirm password reset" : verb + " account"}
        </button>
      </form>
    </Modal>
  );
}

function CaseAccess({
  accounts,
  revision,
  onChanged,
}: {
  accounts: User[];
  revision: number;
  onChanged: () => void;
}) {
  const [search, setSearch] = useState("");
  const [casePage, setCasePage] = useState(1);
  const [selected, setSelected] = useState<Case>();
  const [page, setPage] = useState(1);
  const [revoking, setRevoking] = useState<Grant>();
  const cases = useData<Page<Case>>(
    "/cases" + query({ q: search, sort: "title", limit: 40, page: casePage }),
  );
  const path = selected ? "/cases/" + selected.id + "/access" : "";
  const grants = useData<Grants>(
    path ? path + query({ page }) : null,
    revision,
  );
  const action = useAction();
  const revoke = useAction();
  function submitGrant(userId: string, method: "PUT" | "DELETE") {
    return api(path + "/" + userId, method);
  }
  function reload() {
    setPage(1);
    grants.refresh();
    onChanged();
  }
  return (
    <Panel
      title="Investigation access"
      hint="Review and manage explicit case grants. Administrators have role-based access."
    >
      <div className="panel-body form">
        <label>
          Find an investigation
          <input
            value={search}
            placeholder="Title or description"
            onChange={(event) => {
              setSearch(event.target.value);
              setCasePage(1);
            }}
          />
        </label>
        <Load state={cases}>
          {(data) => (
            <>
              <label htmlFor="managed-case">Investigation</label>
              <select
                id="managed-case"
                value={selected?.id ?? ""}
                onChange={(event) => {
                  setSelected(
                    data.items.find(({ id }) => id === event.target.value),
                  );
                  setPage(1);
                }}
              >
                <option value="">Choose an investigation</option>
                {selected &&
                  !data.items.some(({ id }) => id === selected.id) && (
                    <option value={selected.id}>{selected.title}</option>
                  )}
                {data.items.map(({ id, title }) => (
                  <option key={id} value={id}>
                    {title}
                  </option>
                ))}
              </select>
              <Pager data={data} go={setCasePage} />
            </>
          )}
        </Load>
        {!selected && (
          <Empty>Select an investigation to view its current grants.</Empty>
        )}
        <Load state={grants}>
          {(data) => {
            const eligible = accounts.filter(
              ({ id, role, disabled_at }) =>
                role === "investigator" &&
                !disabled_at &&
                id !== data.owner.id &&
                !data.items.some((grant) => grant.user_id === id),
            );
            return (
              <>
                <p>
                  Case owner <strong>{data.owner.username}</strong>
                  {data.owner.disabled_at ? " · Disabled" : ""}
                </p>
                <Table
                  headers={[
                    "Granted account",
                    "Status",
                    "Granted (UTC)",
                    "Actions",
                  ]}
                  empty="This case has no explicit grants."
                  rows={data.items.map((grant) => [
                    grant.username,
                    <Badge value={grant.disabled_at ? "disabled" : "active"} />,
                    grant.created_at ? date(grant.created_at) : "Legacy grant",
                    <button onClick={() => setRevoking(grant)}>
                      Revoke access
                    </button>,
                  ])}
                />
                <Pager data={data} go={setPage} />
                {eligible.length > 0 && (
                  <form
                    className="form compact-access-form"
                    onSubmit={(event) => {
                      const form = event.currentTarget;
                      const values = formData(event);
                      void action.run(async () => {
                        await submitGrant(
                          String(values.get("recipient")),
                          "PUT",
                        );
                        form.reset();
                        reload();
                      }, "Case access granted.");
                    }}
                  >
                    <label htmlFor="grant-recipient">Grant access to</label>
                    <select
                      id="grant-recipient"
                      name="recipient"
                      required
                      defaultValue=""
                    >
                      <option value="" disabled>
                        Select an investigator
                      </option>
                      {eligible.map(({ id, username }) => (
                        <option key={id} value={id}>
                          {username}
                        </option>
                      ))}
                    </select>
                    <button className="primary" disabled={action.busy}>
                      Grant access
                    </button>
                  </form>
                )}
                {!eligible.length && (
                  <p className="muted">
                    No eligible local investigators on this view.
                  </p>
                )}
              </>
            );
          }}
        </Load>
        <Feedback error={action.error} message={action.message} />
        {revoking && selected && (
          <Modal
            title="Revoke case access"
            close={() => setRevoking(undefined)}
          >
            <p>
              Revoke <strong>{revoking.username}</strong>’s explicit access to{" "}
              <strong>{selected.title}</strong>?
            </p>
            <Feedback error={revoke.error} />
            <button
              disabled={revoke.busy}
              onClick={() =>
                void revoke.run(async () => {
                  await submitGrant(revoking.user_id, "DELETE");
                  setRevoking(undefined);
                  reload();
                })
              }
            >
              Confirm revoke
            </button>
          </Modal>
        )}
      </div>
    </Panel>
  );
}

export function AdminSettings({ user }: { user: User }) {
  const accounts = useData<User[]>("/users");
  const [revision, setRevision] = useState(0);
  const [auditPage, setAuditPage] = useState(1);
  const audit = useData<Page<Activity>>(
    "/users/audit" + query({ page: auditPage }),
    revision,
  );
  const [create, setCreate] = useState(false);
  const [message, setMessage] = useState("");
  const [manage, setManage] = useState<{
    target: User;
    mode: "status" | "password";
  }>();
  const action = useAction();
  function updated(result: string) {
    setMessage(result);
    setManage(undefined);
    setCreate(false);
    accounts.refresh();
    setRevision((value) => value + 1);
  }
  return (
    <div className="settings-grid">
      <Panel
        title="Local accounts"
        hint="Manage investigator and administrator sign-in."
        action={
          <button onClick={() => setCreate(true)}>
            <UserPlus size={16} /> Create account
          </button>
        }
      >
        <Feedback message={message} />
        <Load state={accounts}>
          {(users) => (
            <Table
              headers={["Account", "Role", "Status", "Actions"]}
              rows={users.map((account) => [
                <strong>
                  {account.username}
                  {account.id === user.id && <small>Current session</small>}
                </strong>,
                label(account.role),
                <Badge
                  value={
                    account.disabled_at
                      ? "disabled"
                      : account.password_change_required
                        ? "password_reset_pending"
                        : "active"
                  }
                />,
                account.id === user.id ? (
                  "—"
                ) : (
                  <div className="actions">
                    <button
                      onClick={() =>
                        setManage({ target: account, mode: "password" })
                      }
                    >
                      <KeyRound size={14} /> Reset password
                    </button>
                    <button
                      onClick={() =>
                        setManage({ target: account, mode: "status" })
                      }
                    >
                      <LockKeyhole size={14} />{" "}
                      {account.disabled_at ? "Enable" : "Disable"}
                    </button>
                  </div>
                ),
              ])}
            />
          )}
        </Load>
      </Panel>
      <Load state={accounts}>
        {(users) => (
          <CaseAccess
            accounts={users}
            revision={revision}
            onChanged={() => audit.refresh()}
          />
        )}
      </Load>
      <Panel
        title="Access activity"
        hint="Recorded account and case access changes."
      >
        <Load state={audit}>
          {(data) => (
            <>
              <Table
                headers={[
                  "Time (UTC)",
                  "Actor",
                  "Action",
                  "Account",
                  "Investigation",
                ]}
                rows={data.items.map((row) => [
                  date(row.timestamp),
                  row.actor,
                  label(accessActions[row.action] ?? row.action),
                  row.detail || row.actor,
                  row.case_id ? (
                    <a href={"#/cases/" + row.case_id}>Open case</a>
                  ) : (
                    "—"
                  ),
                ])}
              />
              <Pager data={data} go={setAuditPage} />
            </>
          )}
        </Load>
      </Panel>
      {manage && (
        <ManageAccount
          {...manage}
          close={() => setManage(undefined)}
          onDone={updated}
        />
      )}
      {create && (
        <Modal title="Create local account" close={() => setCreate(false)}>
          <form
            className="form"
            onSubmit={(event) => {
              const data = formData(event);
              void action.run(async () => {
                await api("/users", "POST", Object.fromEntries(data));
                updated("Local account created.");
              });
            }}
          >
            <label>
              New username
              <input name="username" required minLength={3} maxLength={64} />
            </label>
            <label>
              Initial password
              <input
                name="password"
                type="password"
                required
                minLength={12}
                maxLength={256}
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
            <Feedback error={action.error} />
            <button className="primary" disabled={action.busy}>
              Create local account
            </button>
          </form>
        </Modal>
      )}
    </div>
  );
}
