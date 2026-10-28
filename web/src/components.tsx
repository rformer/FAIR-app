import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  Button,
  Dialog,
  DialogTrigger,
  FieldError,
  Form,
  Heading,
  Label,
  Modal,
  TextArea,
  TextField,
} from "react-aria-components";
import { ApiError, describe, getJSON } from "./api";

export interface Loaded<T> {
  data?: T;
  error?: unknown;
  loading: boolean;
  reload: () => void;
}

/** Fetches path; reload() fetches again (after an action). */
export function useApi<T>(path: string): Loaded<T> {
  const [state, setState] = useState<{ data?: T; error?: unknown; loading: boolean }>({ loading: true });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const ac = new AbortController();
    setState((s) => ({ ...s, loading: true }));
    getJSON<T>(path, ac.signal).then(
      (data) => setState({ data, loading: false }),
      (error: unknown) => {
        if (!ac.signal.aborted) setState({ error, loading: false });
      },
    );
    return () => ac.abort();
  }, [path, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}

export type Tone = "ok" | "info" | "warn" | "bad" | "muted";

/** Status is always text; colour only reinforces it (WCAG 1.4.1). */
export function Badge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Section({ id, title, children, intro }: { id: string; title: string; intro?: ReactNode; children: ReactNode }) {
  return (
    <section className="card" aria-labelledby={`${id}-h`} id={id}>
      <h2 id={`${id}-h`}>{title}</h2>
      {intro ? <p className="muted">{intro}</p> : null}
      {children}
    </section>
  );
}

/** Loading and error states of a section's data. */
export function Status<T>({ loaded, children }: { loaded: Loaded<T>; children: (data: T) => ReactNode }) {
  if (loaded.loading && loaded.data === undefined) {
    return (
      <p role="status" className="loading">
        Loading…
      </p>
    );
  }
  if (loaded.error !== undefined) {
    return (
      <p role="alert" className="error-text">
        {describe(loaded.error)}
      </p>
    );
  }
  return <>{loaded.data !== undefined ? children(loaded.data) : null}</>;
}

/**
 * An action that needs a written reason (acknowledge, renew): a button that
 * opens a dialog with a required text area. onSubmit throws to keep the
 * dialog open with the error announced.
 */
export function ReasonAction({
  label,
  title,
  fieldLabel,
  description,
  submitLabel,
  onSubmit,
}: {
  label: string;
  title: string;
  fieldLabel: string;
  description?: ReactNode;
  submitLabel: string;
  onSubmit: (reason: string) => Promise<void>;
}) {
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  return (
    <DialogTrigger onOpenChange={() => setError(undefined)}>
      <Button>{label}</Button>
      <Modal isDismissable>
        <Dialog>
          {({ close }) => (
            <Form
              onSubmit={async (e) => {
                e.preventDefault();
                const reason = String(new FormData(e.currentTarget).get("reason") ?? "").trim();
                if (!reason) {
                  setError("A reason is required.");
                  return;
                }
                setBusy(true);
                try {
                  await onSubmit(reason);
                  close();
                } catch (err) {
                  setError(err instanceof ApiError || err instanceof Error ? describe(err) : String(err));
                } finally {
                  setBusy(false);
                }
              }}
            >
              <Heading slot="title">{title}</Heading>
              {description ? <div>{description}</div> : null}
              <TextField name="reason" isRequired>
                <Label>{fieldLabel}</Label>
                <TextArea rows={3} />
                <FieldError />
              </TextField>
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
              <div className="actions">
                <Button type="submit" className="react-aria-Button primary" isDisabled={busy}>
                  {submitLabel}
                </Button>
                <Button slot="close">Cancel</Button>
              </div>
            </Form>
          )}
        </Dialog>
      </Modal>
    </DialogTrigger>
  );
}

/** A confirmation without a reason (acknowledge a grant). */
export function ConfirmAction({
  label,
  title,
  description,
  confirmLabel,
  onConfirm,
}: {
  label: string;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  onConfirm: () => Promise<void>;
}) {
  const [error, setError] = useState<string>();
  return (
    <DialogTrigger onOpenChange={() => setError(undefined)}>
      <Button>{label}</Button>
      <Modal isDismissable>
        <Dialog>
          {({ close }) => (
            <>
              <Heading slot="title">{title}</Heading>
              <div>{description}</div>
              {error ? (
                <p role="alert" className="error-text">
                  {error}
                </p>
              ) : null}
              <div className="actions">
                <Button
                  className="react-aria-Button primary"
                  onPress={async () => {
                    try {
                      await onConfirm();
                      close();
                    } catch (err) {
                      setError(describe(err));
                    }
                  }}
                >
                  {confirmLabel}
                </Button>
                <Button slot="close">Cancel</Button>
              </div>
            </>
          )}
        </Dialog>
      </Modal>
    </DialogTrigger>
  );
}
