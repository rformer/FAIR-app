import { useEffect, useState, type ReactNode } from "react";
import { Button, Dialog, FieldError, Form, Heading, Label, Modal, TextArea, TextField } from "react-aria-components";
import { ApiError, attachmentName, describe, getFile, ReasonCancelled } from "./api";
import { save } from "./charts/export.ts";

// F-010 T-17 (F-010-AC-16; design §3.6, OQ7): the reason prompt. Where
// export.reason_required is in force for the data an export or download
// covers, the service refuses it with 400 reason_required; withReason then
// asks for a reason in a dialog and tries once more with it. The pages do
// not guess where the rule applies: the service decides, every time.

type Ask = (detail: string) => Promise<string | null>;

let ask: Ask | null = null;

export function isReasonRequired(err: unknown): boolean {
  return err instanceof ApiError && err.status === 400 && err.code === "reason_required";
}

/**
 * Runs attempt without a reason; if the service asks for one, prompts and
 * runs it again with the reason given. Throws ReasonCancelled when the
 * person closes the prompt.
 */
export async function withReason<T>(attempt: (reason?: string) => Promise<T>): Promise<T> {
  try {
    return await attempt();
  } catch (err) {
    if (!isReasonRequired(err) || !ask) throw err;
    const reason = await ask((err as ApiError).detail);
    if (reason === null) throw new ReasonCancelled();
    return attempt(reason);
  }
}

/** The dialog withReason opens; mounted once by the app. */
export function ReasonPrompt() {
  const [pending, setPending] = useState<{ detail: string; resolve: (r: string | null) => void } | null>(null);
  const [error, setError] = useState<string>();
  useEffect(() => {
    ask = (detail) =>
      new Promise((resolve) => {
        setError(undefined);
        setPending({ detail, resolve });
      });
    return () => {
      ask = null;
    };
  }, []);
  const finish = (r: string | null) => {
    pending?.resolve(r);
    setPending(null);
  };
  return (
    <Modal isDismissable isOpen={pending !== null} onOpenChange={(open) => (open ? undefined : finish(null))}>
      <Dialog>
        <Form
          onSubmit={(e) => {
            e.preventDefault();
            const reason = String(new FormData(e.currentTarget).get("reason") ?? "").trim();
            if (!reason) {
              setError("A reason is required.");
              return;
            }
            finish(reason);
          }}
        >
          <Heading slot="title">Why are you taking this data out?</Heading>
          <p>This data is covered by a rule that every export records its reason. Your reason is kept in the audit trail with the export.</p>
          <TextField name="reason" isRequired maxLength={500} autoFocus>
            <Label>Reason for the export</Label>
            <TextArea rows={3} />
            <FieldError />
          </TextField>
          {error ? (
            <p role="alert" className="error-text">
              {error}
            </p>
          ) : null}
          <div className="actions">
            <Button type="submit" className="react-aria-Button primary">
              Continue
            </Button>
            <Button onPress={() => finish(null)}>Cancel</Button>
          </div>
        </Form>
      </Dialog>
    </Modal>
  );
}

/**
 * A button that downloads a file from the API, asking for a reason when the
 * service requires one; onDone gets the response (its headers, e.g. the
 * digest) once the file is saved.
 */
export function DownloadButton({
  href,
  fallbackName,
  children,
  onDone,
}: {
  href: string;
  fallbackName: string;
  children: ReactNode;
  onDone?: (resp: Response) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <>
      <Button
        isDisabled={busy}
        onPress={async () => {
          setBusy(true);
          setError(undefined);
          try {
            const resp = await withReason((reason) => getFile(href, reason));
            save(await resp.blob(), attachmentName(resp, fallbackName));
            onDone?.(resp);
          } catch (err) {
            setError(describe(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        {children}
      </Button>
      {error ? (
        <span role="alert" className="error-text">
          {" "}
          {error}
        </span>
      ) : null}
    </>
  );
}
