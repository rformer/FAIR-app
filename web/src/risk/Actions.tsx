import { useState } from "react";
import { Button, Dialog, DialogTrigger, Heading, Modal } from "react-aria-components";
import { describe, send } from "../api";
import { ReasonAction } from "../components";
import type { BU } from "./types";

// F-003 T-13 (AC-19, AC-22): archiving, restoring and moving, each with a
// reason recorded in the audit trail.

/** Archive or restore a scenario, library entry or control. */
export function ArchiveAction({ base, archived, what, onDone }: { base: string; archived: boolean; what: string; onDone: () => void }) {
  return archived ? (
    <ReasonAction
      label="Restore"
      title={`Restore this ${what}`}
      fieldLabel="Reason"
      description={<p>It becomes active again and can be changed.</p>}
      submitLabel="Restore"
      onSubmit={async (reason) => {
        await send("POST", `${base}/restore`, { reason });
        onDone();
      }}
    />
  ) : (
    <ReasonAction
      label="Archive"
      title={`Archive this ${what}`}
      fieldLabel="Reason"
      description={<p>It becomes read-only and leaves the active lists. Its history is kept, and it can be restored.</p>}
      submitLabel="Archive"
      onSubmit={async (reason) => {
        await send("POST", `${base}/archive`, { reason });
        onDone();
      }}
    />
  );
}

/** Move a scenario to another BU where the user may edit scenarios. */
export function MoveAction({ id, from, bus, onDone }: { id: string; from: string; bus: BU[]; onDone: () => void }) {
  const targets = bus.filter((b) => b.id !== from);
  const [to, setTo] = useState(targets[0]?.id ?? "");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  if (targets.length === 0) return null;
  return (
    <DialogTrigger onOpenChange={() => setError(undefined)}>
      <Button>Move</Button>
      <Modal isDismissable>
        <Dialog>
          {({ close }) => (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!reason.trim()) {
                  setError("A reason is required.");
                  return;
                }
                setBusy(true);
                try {
                  await send("POST", `/api/v1/scenarios/${id}/move`, { to_bu_id: to, reason });
                  close();
                  onDone();
                } catch (err) {
                  setError(describe(err));
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Heading slot="title">Move this scenario</Heading>
              <p>Its versions move with it. A scenario inside a restricted business unit cannot leave it.</p>
              <div className="field">
                <label htmlFor="move-to">Move to</label>
                <select id="move-to" value={to} onChange={(e) => setTo(e.target.value)}>
                  {targets.map((b) => (
                    <option key={b.id} value={b.id}>
                      {b.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label htmlFor="move-reason">Reason</label>
                <textarea id="move-reason" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} />
              </div>
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
              <div className="actions">
                <Button type="submit" className="react-aria-Button primary" isDisabled={busy}>
                  Move
                </Button>
                <Button slot="close">Cancel</Button>
              </div>
            </form>
          )}
        </Dialog>
      </Modal>
    </DialogTrigger>
  );
}
