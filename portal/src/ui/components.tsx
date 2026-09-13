/**
 * The portal's shared interface pieces.
 *
 * Three things they all have in common, and each is a decision rather than a default.
 *
 * **Text is text.** Nothing in this file, or anywhere in `src/`, assigns `innerHTML` or uses
 * `dangerouslySetInnerHTML` -- Biome's `noDangerouslySetInnerHtml` is an error and
 * `tests/rendering.test.tsx` scans the source for the rest. Server-supplied strings (a
 * workspace name, an invited address, a consent paragraph) are rendered as React children,
 * which escapes them by construction.
 *
 * **A control that is disabled says why.** A greyed-out button with no explanation is how an
 * interface tells a viewer they did something wrong when in fact their role does not permit
 * it. Every permission-aware control here takes a `reason` and renders it.
 *
 * **State changes are announced.** Errors and confirmations go into a live region, so a
 * screen-reader user learns that a save succeeded without having to go looking for the
 * sentence.
 */

import { type FormEvent, type ReactNode, useEffect, useId, useRef, useState } from "react";

// ------------------------------------------------------------------------------- status

export function Spinner({ label = "Loading" }: { label?: string }) {
  return (
    <p className="status" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </p>
  );
}

/**
 * A message a customer needs to notice.
 *
 * `role="alert"` for a failure -- it interrupts, which is right when an action did not
 * happen -- and `role="status"` for everything else, which does not.
 */
export function Notice({
  kind,
  children,
  onDismiss,
}: {
  kind: "error" | "success" | "info" | "warning";
  children: ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <div className={`notice notice-${kind}`} role={kind === "error" ? "alert" : "status"}>
      <div className="notice-body">{children}</div>
      {onDismiss ? (
        <button type="button" className="link-button" onClick={onDismiss}>
          Dismiss
        </button>
      ) : null}
    </div>
  );
}

/** What a page shows when there is genuinely nothing, which is not the same as an error. */
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children ? <div className="empty-body">{children}</div> : null}
    </div>
  );
}

/**
 * A feature that exists in the product and is not built yet.
 *
 * The roadmap is explicit that Evaluation, Jobs, Results and Billing get navigation at this
 * milestone and that none of them may be simulated. So this component says what the thing
 * will be, says plainly that it is not available, and shows **no** fabricated figure, table,
 * chart or sample record. `aria-disabled` rather than a removed link: the customer can see
 * the shape of the product they are buying into.
 */
export function NotYetAvailable({
  title,
  milestone,
  children,
}: {
  title: string;
  milestone: string;
  children: ReactNode;
}) {
  return (
    <section className="unavailable" aria-labelledby={`unavailable-${milestone}`}>
      <h2 id={`unavailable-${milestone}`}>{title}</h2>
      <p className="unavailable-badge">Not available yet</p>
      <div className="unavailable-body">{children}</div>
      <p className="unavailable-note">
        Nothing on this page is simulated. When {title.toLowerCase()} is available, this is where it
        will appear.
      </p>
    </section>
  );
}

// -------------------------------------------------------------------------------- forms

interface FieldProps {
  label: string;
  name: string;
  type?: "text" | "email" | "password" | "url";
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
  autoComplete?: string;
  hint?: string;
  error?: string | null;
  maxLength?: number;
  disabled?: boolean;
  inputMode?: "text" | "email";
}

/**
 * One labelled input.
 *
 * The label is a real `<label for>`, the hint and the error are wired through
 * `aria-describedby`, and an invalid field carries `aria-invalid`. That combination is what
 * makes a screen reader read "Email address, invalid entry, that address is not acceptable"
 * instead of reading the input and leaving the customer to find the red text.
 */
export function Field({
  label,
  name,
  type = "text",
  value,
  onChange,
  required = false,
  autoComplete,
  hint,
  error,
  maxLength,
  disabled = false,
  inputMode,
}: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint ? hintId : null, error ? errorId : null].filter(Boolean).join(" ");
  return (
    <div className="field">
      <label htmlFor={id}>
        {label}
        {required ? <span aria-hidden="true"> *</span> : null}
      </label>
      <input
        id={id}
        name={name}
        type={type}
        value={value}
        required={required}
        disabled={disabled}
        maxLength={maxLength}
        {...(autoComplete ? { autoComplete } : {})}
        {...(inputMode ? { inputMode } : {})}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy || undefined}
        onChange={(event) => onChange(event.target.value)}
      />
      {hint ? (
        <p className="field-hint" id={hintId}>
          {hint}
        </p>
      ) : null}
      {error ? (
        <p className="field-error" id={errorId}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function Select<T extends string>({
  label,
  value,
  options,
  onChange,
  disabled = false,
  hint,
}: {
  label: string;
  value: T;
  options: ReadonlyArray<{ value: T; label: string }>;
  onChange: (value: T) => void;
  disabled?: boolean;
  hint?: string;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        aria-describedby={hint ? hintId : undefined}
        onChange={(event) => onChange(event.target.value as T)}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {hint ? (
        <p className="field-hint" id={hintId}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

export function Checkbox({
  label,
  checked,
  onChange,
  disabled = false,
  hint,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  hint?: string;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  return (
    <div className="field field-checkbox">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        aria-describedby={hint ? hintId : undefined}
        onChange={(event) => onChange(event.target.checked)}
      />
      <label htmlFor={id}>{label}</label>
      {hint ? (
        <p className="field-hint" id={hintId}>
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/**
 * A button whose availability depends on the customer's role.
 *
 * **This hides nothing that the server does not also refuse.** Hiding a control is an
 * interface decision, not an authorization one: the same operation attempted directly is
 * still checked against the membership as it is at that moment. What this adds is that a
 * viewer is told *why* the control is unavailable instead of being left to guess.
 */
export function PermissionButton({
  allowed,
  reason,
  children,
  onClick,
  type = "button",
  variant = "default",
  busy = false,
}: {
  allowed: boolean;
  reason: string;
  children: ReactNode;
  onClick?: () => void;
  type?: "button" | "submit";
  variant?: "default" | "primary" | "danger";
  busy?: boolean;
}) {
  const id = useId();
  return (
    <span className="permission-button">
      <button
        type={type}
        className={`button button-${variant}`}
        disabled={!allowed || busy}
        aria-describedby={allowed ? undefined : id}
        {...(onClick ? { onClick } : {})}
      >
        {busy ? "Working…" : children}
      </button>
      {allowed ? null : (
        <span className="permission-reason" id={id}>
          {reason}
        </span>
      )}
    </span>
  );
}

export function Button({
  children,
  onClick,
  type = "button",
  variant = "default",
  busy = false,
  disabled = false,
}: {
  children: ReactNode;
  onClick?: () => void;
  type?: "button" | "submit";
  variant?: "default" | "primary" | "danger" | "quiet";
  busy?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type={type}
      className={`button button-${variant}`}
      disabled={disabled || busy}
      {...(onClick ? { onClick } : {})}
    >
      {busy ? "Working…" : children}
    </button>
  );
}

export function Form({
  onSubmit,
  children,
  label,
}: {
  onSubmit: () => void;
  children: ReactNode;
  label: string;
}) {
  const handle = (event: FormEvent) => {
    event.preventDefault();
    onSubmit();
  };
  return (
    <form onSubmit={handle} aria-label={label} noValidate>
      {children}
    </form>
  );
}

// ------------------------------------------------------------------------------ dialogs

/**
 * A modal dialog with the keyboard behaviour a dialog is supposed to have.
 *
 * `role="dialog"` and `aria-modal`, focus moved to the dialog when it opens, focus **kept
 * inside** while it is open, Escape closes it, and focus returned to whatever opened it.
 * Written out rather than pulled in, because the whole of it is the forty lines below and a
 * dialog library would be a dependency for one component.
 */
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Wrap Tab and Shift+Tab at the edges of a container, so focus cannot leave it.
 *
 * This is the whole of a focus trap. Without it, tabbing past the last control in a dialog
 * moves focus to the page behind -- which a sighted user notices and a screen-reader user
 * does not, leaving them reading a page they believe is covered.
 */
function keepTabInside(event: KeyboardEvent, container: HTMLElement): void {
  const focusable = container.querySelectorAll<HTMLElement>(FOCUSABLE);
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (!first || !last) return;
  const atStart = event.shiftKey && document.activeElement === first;
  const atEnd = !event.shiftKey && document.activeElement === last;
  if (!atStart && !atEnd) return;
  event.preventDefault();
  (atStart ? last : first).focus();
}

export function Dialog({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const openerRef = useRef<Element | null>(null);

  useEffect(() => {
    openerRef.current = document.activeElement;
    const node = ref.current;
    node?.focus();
    return () => {
      const opener = openerRef.current;
      if (opener instanceof HTMLElement && document.contains(opener)) opener.focus();
    };
  }, []);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key === "Tab" && ref.current) keepTabInside(event, ref.current);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  return (
    <div className="dialog-backdrop">
      <div
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        ref={ref}
        tabIndex={-1}
      >
        <h2 id={titleId}>{title}</h2>
        {children}
      </div>
    </div>
  );
}

// -------------------------------------------------------------------------------- table

export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  empty,
}: {
  caption: string;
  columns: ReadonlyArray<{ header: string; cell: (row: T) => ReactNode }>;
  rows: readonly T[];
  rowKey: (row: T) => string;
  empty: ReactNode;
}) {
  if (rows.length === 0) return <>{empty}</>;
  return (
    <div className="table-scroll">
      <table>
        <caption>{caption}</caption>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.header} scope="col">
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={rowKey(row)}>
              {columns.map((column) => (
                <td key={column.header}>{column.cell(row)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ------------------------------------------------------------------------------- secret

/**
 * A newly minted API credential, shown once.
 *
 * The value lives in this component's props and in the DOM node below, and nowhere else: not
 * in a URL, not in a cookie, not in browser storage (which throws in tests), not in a log
 * (there is no logging), not in the session context, and not in any structure that outlives
 * the page. Dismissing it removes the node, and the API has no route that returns it again.
 *
 * The copy button uses the async clipboard API and reports failure rather than falling back
 * to `document.execCommand`, whose fallback path works by putting the value in a temporary
 * DOM node and selecting it -- which is a second copy of the secret in the page.
 */
export function OneTimeSecret({ secret, onDismiss }: { secret: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState<"idle" | "done" | "failed">("idle");
  const id = useId();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied("done");
    } catch {
      setCopied("failed");
    }
  };
  return (
    <div className="one-time-secret" role="alert" aria-labelledby={id}>
      <h3 id={id}>Copy this key now</h3>
      <p>
        This is the only time it is shown. Firmbatch stores a fingerprint of it, not the key, so it
        cannot be shown again — if it is lost, rotate the credential to get a new one.
      </p>
      <output className="secret-value" aria-label="New API credential">
        {secret}
      </output>
      <div className="row">
        <Button onClick={() => void copy()}>Copy to clipboard</Button>
        <Button variant="quiet" onClick={onDismiss}>
          I have saved it
        </Button>
      </div>
      <p aria-live="polite" className="copy-status">
        {copied === "done" ? "Copied." : null}
        {copied === "failed" ? "Could not copy. Select the key and copy it manually." : null}
      </p>
    </div>
  );
}
