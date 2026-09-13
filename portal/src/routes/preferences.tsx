/**
 * What the customer intends to run, where it may run, and their acknowledgement of the
 * consent and subprocessor statement.
 *
 * The roadmap asks M3.2 to "capture the customer's desired policy, profile and preferences
 * for later use **without claiming a quote or an execution**", and to draft consent text that
 * states `provider_policy`'s v1 scope exactly. Both halves are here, and the qualification is
 * visible on the page rather than only in a comment: this form says, in the interface, that
 * it records intent and prices and schedules nothing.
 *
 * The consent text itself is **not written here**. It is served by `GET /v1/consent` and
 * rendered from that response, so the version a workspace acknowledges is by construction the
 * version it was shown -- a second copy in the frontend would be a second copy that can
 * drift from the one the database validates against.
 *
 * The exclusion v1 cannot honour -- Amazon, because the payload plane is S3 for every tenant
 * -- is not silently refused and not silently accepted. It is accepted, recorded, and
 * flagged, because a customer who requires it is a fact the business needs; what would be
 * dishonest is taking the exclusion and implying it will be met.
 *
 * **Every save names the workspace this form was loaded for.** The session is shared between
 * tabs, and another tab can switch it to a different workspace while this form is open. The
 * API compares the workspace the form names with the one the session is bound to at the
 * moment of the write and refuses a mismatch with `409 workspace_mismatch`; this page then
 * says nothing was saved and reloads itself for the current workspace, rather than ever
 * showing one workspace's values under another workspace's name.
 */

import { useCallback, useEffect, useState } from "react";
import { consent as consentApi, workspace as workspaceApi } from "../api/endpoints.ts";
import { ApiError } from "../api/errors.ts";
import type { ConsentDocument, EvaluationIntent, WorkspacePreferences } from "../api/types.ts";
import { afterRefusal, shows, useSession } from "../auth/session.tsx";
import { type PageTicket, reads, usePageRequests } from "../lib/requests.ts";
import {
  Button,
  Checkbox,
  Field,
  Form,
  Notice,
  PermissionButton,
  Select,
  Spinner,
} from "../ui/components.tsx";
import { OTHER_WORKSPACE_ANSWERED } from "./team.tsx";

/**
 * The closed vocabularies, rendered. Every value is one the API accepts and the database
 * constrains; the labels are this page's, the values are not.
 */
const PROVIDER_CLASSES: ReadonlyArray<{ value: string; label: string; note?: string }> = [
  {
    value: "amazon",
    label: "Amazon Web Services",
    note: "Excluding Amazon cannot be honoured in v1: your inputs and outputs are stored in S3.",
  },
  { value: "google", label: "Google Cloud" },
  { value: "microsoft", label: "Microsoft Azure" },
  { value: "verda", label: "Verda" },
];

const REGION_GROUPS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "EU", label: "European Union" },
];

const INTENTS: ReadonlyArray<{ value: EvaluationIntent; label: string }> = [
  { value: "undecided", label: "Not decided yet" },
  { value: "planning_evaluation", label: "We plan to run the free evaluation" },
  { value: "evaluation_not_needed", label: "We do not need an evaluation" },
];

/** What the page says when the workspace moved underneath it. Nothing was saved. */
const WORKSPACE_MOVED =
  "This form was loaded for a different workspace than the one this session now has selected. Nothing was saved. The page has been reloaded for the current workspace; check it before saving again.";

function when(value: string | null): string {
  if (value === null) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toLocaleString();
}

/**
 * The consent statement, as the API served it, and the acknowledgement.
 *
 * Its own component because it is its own thing: it renders text this application does not
 * author, tracks a version rather than a value, and fails independently of the settings form
 * above it. The `document === null` branch is a consent-service outage, and it deliberately
 * does **not** stop a customer editing the settings they came here for.
 */
function ConsentSection({
  document,
  preferences: current,
  allowed,
  reason,
  busy,
  onAcknowledge,
}: {
  document: ConsentDocument | null;
  preferences: WorkspacePreferences | null;
  allowed: boolean;
  reason: string;
  busy: boolean;
  onAcknowledge: () => void;
}) {
  const acknowledgedCurrent =
    current !== null && current.consent_version === current.current_consent_version;
  const acknowledgedEarlier = !acknowledgedCurrent && Boolean(current?.consent_version);

  return (
    <section aria-labelledby="consent">
      <h2 id="consent">Consent and subprocessors</h2>
      {document === null ? (
        <Notice kind="error">The consent statement could not be loaded.</Notice>
      ) : (
        <>
          <h3>{document.title}</h3>
          <p className="muted">{document.authority}</p>
          {document.sections.map((section) => (
            <div key={section.heading} className="consent-section">
              <h4>{section.heading}</h4>
              {section.body.map((paragraph) => (
                <p key={paragraph}>{paragraph}</p>
              ))}
            </div>
          ))}
          {acknowledgedCurrent ? (
            <Notice kind="success">
              Acknowledged {when(current?.consent_acknowledged_at ?? null)}, version{" "}
              {current?.consent_version}.
            </Notice>
          ) : (
            <>
              {acknowledgedEarlier ? (
                <Notice kind="info">
                  This workspace acknowledged an earlier version ({current?.consent_version}). The
                  statement above has changed.
                </Notice>
              ) : null}
              <PermissionButton
                variant="primary"
                busy={busy}
                allowed={allowed}
                reason={reason}
                onClick={onAcknowledge}
              >
                Acknowledge this statement
              </PermissionButton>
            </>
          )}
          <p className="muted">
            Acknowledging records the version, the time and the account. It creates no job, quote,
            invoice or commitment.
          </p>
        </>
      )}
    </section>
  );
}

export function PreferencesPage() {
  const session = useSession();
  const { reconcile, refresh } = session;
  const { beginLoad, beginAction, live, latest, mounted } = usePageRequests(session, {
    scoped: true,
  });
  const [preferences, setPreferences] = useState<WorkspacePreferences | null>(null);
  const [document, setDocument] = useState<ConsentDocument | null>(null);
  const [regions, setRegions] = useState<string[]>([]);
  const [excluded, setExcluded] = useState<string[]>([]);
  const [note, setNote] = useState("");
  const [intent, setIntent] = useState<EvaluationIntent>("undecided");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [acknowledging, setAcknowledging] = useState(false);
  // Two error states, deliberately. `problem` is "the thing you just asked for did not
  // happen"; `loadProblem` is "these settings could not be fetched". They have different
  // lifetimes: a reload that followed a failed save must not erase the explanation of why
  // the save failed, which is the one sentence the customer is looking for.
  const [problem, setProblem] = useState<string | null>(null);
  const [loadProblem, setLoadProblem] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const roleMayWrite = shows.workspaceSettings(session.role) || session.role === "member";
  // Saving is also refused until the current settings have actually been read. Otherwise a
  // failed load leaves the form holding defaults that are not this workspace's, and the next
  // Save silently replaces real settings with blanks.
  const mayWrite = roleMayWrite && preferences !== null;

  // Stable, so `load` can depend on it honestly rather than closing over a new function every
  // render. The form always shows what the server last returned: a save that the server
  // adjusted (a deduplicated array, a trimmed note) is reflected here rather than leaving the
  // fields showing what was typed.
  const apply = useCallback((value: WorkspacePreferences) => {
    setPreferences(value);
    setRegions(value.region_policy);
    setExcluded(value.excluded_provider_classes);
    setNote(value.model_profile_note ?? "");
    setIntent(value.evaluation_intent);
  }, []);

  /**
   * Load the two independently, and settle them independently.
   *
   * `Promise.all` would have been shorter and is wrong here: the two halves of this page have
   * nothing to do with each other, and rejecting both because one failed leaves the form
   * rendered with **empty values that are not the customer's** -- which is the state in which
   * somebody presses Save and overwrites their own settings with blanks. Failing separately
   * means a consent outage costs the consent section and nothing else.
   *
   * Sets and clears `loadProblem` only, never `problem`: see the two-state comment above.
   * Publishes nothing unless this is still the newest load of a page still showing the
   * workspace it began under, and never a settings row that names another workspace.
   */
  const load = useCallback(
    async (fresh = false) => {
      const ticket = beginLoad();
      setLoading(true);
      const [current, statement] = await Promise.allSettled([
        reads.run(`preferences:${ticket.workspaceId}`, () => workspaceApi.preferences(), { fresh }),
        reads.run("consent", () => consentApi.read(), { fresh }),
      ]);
      if (!latest(ticket)) return;
      if (current.status === "fulfilled" && current.value.workspace_id !== ticket.workspaceId) {
        // The session is bound elsewhere than this page believes: another tab switched it.
        // Nothing of that workspace is rendered here; the binding is re-read, and the page
        // reloads for whatever it turns out to be.
        setLoadProblem(OTHER_WORKSPACE_ANSWERED);
        setLoading(false);
        void refresh(ticket.lease);
        return;
      }
      setDocument(statement.status === "fulfilled" ? statement.value : null);
      if (current.status === "fulfilled") {
        apply(current.value);
        setLoadProblem(null);
        setLoading(false);
        return;
      }
      setLoading(false);
      const outcome = await reconcile(ticket.lease, current.reason, "read");
      if (latest(ticket)) {
        setLoadProblem(
          afterRefusal(
            outcome,
            current.reason instanceof ApiError
              ? current.reason.message
              : "These settings could not be loaded.",
          ),
        );
      }
    },
    [apply, beginLoad, latest, reconcile, refresh],
  );

  // On mount, and again whenever the selected workspace changes while this page stays open.
  const boundWorkspace = session.workspaceId;
  // biome-ignore lint/correctness/useExhaustiveDependencies: the selected workspace is a reason to load again, not an input to the load
  useEffect(() => {
    void load();
  }, [load, boundWorkspace]);

  /**
   * What a failed mutation means for this page.
   *
   * A workspace mismatch is the shared session having moved to another workspace: nothing was
   * saved, and the honest thing to show is the current workspace's settings under its own
   * name, with a sentence saying why the form changed under the customer. A `403` is a role
   * that changed while the page was open: the session re-reads its authority and the controls
   * follow. A `401` is ambiguous and is checked, never believed. Everything else is reported
   * and the form is left as the customer had it. All of it only while the ticket -- the
   * page, the session and the workspace the request was made under -- is still current.
   */
  const failed = async (ticket: PageTicket, error: unknown, fallback: string) => {
    if (!live(ticket)) return;
    if (error instanceof ApiError && error.isWorkspaceMismatch) {
      setProblem(WORKSPACE_MOVED);
      // The session re-reads its binding; the page reloads for the workspace it finds (the
      // effect on the selected workspace), and this ticket's workspace is then history.
      await refresh(ticket.lease);
      return;
    }
    setProblem(
      afterRefusal(
        await reconcile(ticket.lease, error, "mutation"),
        error instanceof ApiError ? error.message : fallback,
      ),
    );
  };

  const save = async () => {
    if (preferences === null) return;
    setBusy(true);
    setProblem(null);
    setSaved(false);
    const ticket = beginAction();
    try {
      // The workspace this form was loaded for, sent with the values and as the header: the
      // API refuses the write if the session has since been switched to another workspace.
      const updated = await workspaceApi.statePreferences(preferences.workspace_id, {
        region_policy: regions,
        excluded_provider_classes: excluded,
        model_profile_note: note.trim() === "" ? null : note.trim(),
        evaluation_intent: intent,
      });
      if (!live(ticket)) return;
      apply(updated);
      setSaved(true);
    } catch (error) {
      await failed(ticket, error, "These settings were not saved.");
    } finally {
      if (mounted()) setBusy(false);
    }
  };

  const acknowledge = async () => {
    if (document === null || preferences === null) return;
    setAcknowledging(true);
    setProblem(null);
    const ticket = beginAction();
    try {
      const updated = await workspaceApi.acknowledgeConsent(
        preferences.workspace_id,
        document.version,
      );
      if (!live(ticket)) return;
      apply(updated);
    } catch (error) {
      await failed(ticket, error, "That acknowledgement was not recorded.");
    } finally {
      if (mounted()) setAcknowledging(false);
    }
  };

  if (loading) return <Spinner label="Loading policy and preferences…" />;

  return (
    <>
      <h1>Policy and preferences</h1>
      <p className="lede">
        What you tell us here is <strong>recorded intent</strong>. It does not create a job, reserve
        capacity, produce a quote or schedule anything. When jobs open, these are the defaults they
        start from.
      </p>

      {loadProblem ? <Notice kind="error">{loadProblem}</Notice> : null}
      {problem ? <Notice kind="error">{problem}</Notice> : null}
      {saved ? (
        <Notice kind="success" onDismiss={() => setSaved(false)}>
          Saved.
        </Notice>
      ) : null}
      {preferences?.unservable_exclusion ? (
        <Notice kind="warning">
          You have excluded Amazon Web Services. In v1 that exclusion cannot be honoured: your
          inputs and outputs are stored in Amazon S3 whatever the execution policy says, so
          Firmbatch would refuse work under it rather than run the work anyway. It is recorded here
          as your requirement.
        </Notice>
      ) : null}

      <Form onSubmit={() => void save()} label="Policy and preferences">
        <section aria-labelledby="placement">
          <h2 id="placement">Where work may run</h2>
          <p className="muted">
            You never choose a placement. These are constraints on the choice Firmbatch makes.
          </p>

          <fieldset>
            <legend>Region</legend>
            {REGION_GROUPS.map((region) => (
              <Checkbox
                key={region.value}
                label={region.label}
                checked={regions.includes(region.value)}
                disabled={!mayWrite}
                onChange={(checked) =>
                  setRegions(
                    checked
                      ? [...regions, region.value]
                      : regions.filter((value) => value !== region.value),
                  )
                }
              />
            ))}
            <p className="field-hint">
              Leave every box clear for no region constraint. Confining work to a region makes it
              more expensive and slower to place.
            </p>
          </fieldset>

          <fieldset>
            <legend>Providers you exclude</legend>
            <p className="field-hint">
              This names <em>whose</em> hardware, never <em>where</em>. It governs execution
              placement only — first placement, every retry, every move to shared capacity and every
              hedge.
            </p>
            {PROVIDER_CLASSES.map((provider) => (
              <Checkbox
                key={provider.value}
                label={provider.label}
                {...(provider.note ? { hint: provider.note } : {})}
                checked={excluded.includes(provider.value)}
                disabled={!mayWrite}
                onChange={(checked) =>
                  setExcluded(
                    checked
                      ? [...excluded, provider.value]
                      : excluded.filter((value) => value !== provider.value),
                  )
                }
              />
            ))}
          </fieldset>
        </section>

        <section aria-labelledby="workload">
          <h2 id="workload">What you expect to run</h2>
          <Field
            label="Model and runtime profile"
            name="model_profile_note"
            value={note}
            onChange={setNote}
            maxLength={200}
            disabled={!mayWrite}
            hint="In your own words. Certified profiles with measured throughput come later; this is a note, not a selection."
          />
          <Select
            label="Do you plan to run the free evaluation?"
            value={intent}
            options={INTENTS}
            disabled={!mayWrite}
            onChange={setIntent}
          />
        </section>

        <PermissionButton
          type="submit"
          variant="primary"
          busy={busy}
          allowed={mayWrite}
          reason={
            roleMayWrite
              ? "These settings could not be read, so they must not be replaced."
              : "A viewer cannot change this workspace's stated policy."
          }
        >
          Save
        </PermissionButton>
      </Form>

      <ConsentSection
        document={document}
        preferences={preferences}
        allowed={mayWrite}
        reason={
          roleMayWrite
            ? "These settings could not be read, so they must not be replaced."
            : "A viewer cannot acknowledge on behalf of this workspace."
        }
        busy={acknowledging}
        onAcknowledge={() => void acknowledge()}
      />

      {preferences?.updated_at ? (
        <p className="muted">Last changed {when(preferences.updated_at)}.</p>
      ) : null}

      <p className="muted">
        <Button variant="quiet" onClick={() => void load(true)}>
          Reload
        </Button>
      </p>
    </>
  );
}
