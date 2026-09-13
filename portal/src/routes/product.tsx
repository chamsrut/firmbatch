/**
 * The overview, and the four product sections the roadmap names as navigation for M3.2.
 *
 * Milestone 3.2's instruction is exact: create clear navigation for Evaluation, Jobs, Results
 * and Billing, and "**do not simulate a completed job or an invoice as a working backend
 * feature**". So each of these pages describes what the section will do, says plainly that it
 * is not available, and contains **no** fabricated job, result, figure, chart, invoice or
 * sample row. There is no placeholder table with grey bars in it, because a placeholder table
 * is a picture of data.
 *
 * The overview's first journey is the one the roadmap asks for: the free 1,000-request
 * evaluation, then conversion to paid flex. It is described as the journey it will be, with
 * the parts that exist today (workspace, team, API credentials, stated policy) linked and
 * working, and the parts that do not marked as such.
 */

import { useSession } from "../auth/session.tsx";
import { Link } from "../lib/router.tsx";
import { NotYetAvailable } from "../ui/components.tsx";

export function OverviewPage() {
  const session = useSession();
  return (
    <>
      <h1>Overview</h1>
      <p className="lede">
        Firmbatch takes a batch of requests, an acceptance policy and a deadline, and returns
        accepted output by that deadline. Machines are rented, used, killed and replaced underneath;
        the job does not notice.
      </p>

      <section aria-labelledby="getting-started">
        <h2 id="getting-started">Getting started</h2>
        <ol className="journey">
          <li className="journey-done">
            <span className="journey-mark" aria-hidden="true">
              ✓
            </span>
            <div>
              <strong>Create a workspace.</strong> Done — you are in{" "}
              {session.workspaces.find((w) => w.workspace_id === session.workspaceId)?.name ??
                "this workspace"}
              .
            </div>
          </li>
          <li>
            <span className="journey-mark" aria-hidden="true">
              2
            </span>
            <div>
              <strong>Invite the people who will use it.</strong>{" "}
              <Link to="/settings/team">Manage your team</Link>.
            </div>
          </li>
          <li>
            <span className="journey-mark" aria-hidden="true">
              3
            </span>
            <div>
              <strong>Say what you intend to run and where it may run.</strong>{" "}
              <Link to="/settings/preferences">Policy and preferences</Link>. This is recorded for
              when jobs open; it does not price or schedule anything.
            </div>
          </li>
          <li>
            <span className="journey-mark" aria-hidden="true">
              4
            </span>
            <div>
              <strong>Create an API credential.</strong>{" "}
              <Link to="/settings/credentials">API credentials</Link>. The SDK and CLI use these.
            </div>
          </li>
          <li className="journey-pending">
            <span className="journey-mark" aria-hidden="true">
              5
            </span>
            <div>
              <strong>Run a free evaluation.</strong> Up to 1,000 requests against your own
              acceptance rules, with a report: pass rate, every failure and the rule that rejected
              it, and cost per thousand accepted units at list price. Not available yet — see{" "}
              <Link to="/evaluation">Evaluation</Link>.
            </div>
          </li>
          <li className="journey-pending">
            <span className="journey-mark" aria-hidden="true">
              6
            </span>
            <div>
              <strong>Convert to paid flex.</strong> A paid job is a new job with its own quote; an
              evaluation never converts itself into one. Not available yet.
            </div>
          </li>
        </ol>
      </section>
    </>
  );
}

export function EvaluationPage() {
  return (
    <>
      <h1>Evaluation</h1>
      <NotYetAvailable title="Evaluation" milestone="evaluation">
        <p>
          An evaluation is a free job: up to <strong>1,000 requests</strong>, one per corpus, run
          against your own acceptance rules. It has no quote and produces no invoice.
        </p>
        <p>
          The report is produced in every case — including a failed, partial or cancelled run — and
          carries:
        </p>
        <ul>
          <li>the pass rate against your own rules;</li>
          <li>every failure, with the rule that rejected it;</li>
          <li>cost per thousand accepted units at list price;</li>
          <li>the escalation rate: the share of requests that pass only on a larger model.</li>
        </ul>
        <p>
          An evaluation never converts itself into a paid job. A paid job is a new job with its own
          quote and its own acceptance record.
        </p>
        <p>
          In the meantime, you can{" "}
          <Link to="/settings/preferences">record what you intend to run</Link>, so it is ready when
          evaluation opens.
        </p>
      </NotYetAvailable>
    </>
  );
}

export function JobsPage() {
  return (
    <>
      <h1>Jobs</h1>
      <NotYetAvailable title="Jobs" milestone="jobs">
        <p>
          A job is a batch of requests, an acceptance policy, and a deadline. You say what is
          required and by when; Firmbatch chooses the provider, the GPU class and the execution
          time.
        </p>
        <p>
          This page will list your jobs with their state, their deadline and their accepted counts.
          There is nothing to show yet, and nothing here is a placeholder for data that exists
          elsewhere — job submission is not built.
        </p>
      </NotYetAvailable>
    </>
  );
}

export function ResultsPage() {
  return (
    <>
      <h1>Results</h1>
      <NotYetAvailable title="Results" milestone="results">
        <p>
          Results are the accepted output of a job, and the record of what was rejected and by which
          rule. They are fetched with a link scoped to your workspace; output never passes through
          this page.
        </p>
        <p>Results appear once jobs do.</p>
      </NotYetAvailable>
    </>
  );
}

export function BillingPage() {
  return (
    <>
      <h1>Billing</h1>
      <NotYetAvailable title="Billing" milestone="billing">
        <p>
          Billing will carry your billing identity and address, your payment method, and Firmbatch
          invoices and credits.
        </p>
        <p>
          Evaluation is free: it needs no payment method and creates no invoice. Paid work is quoted
          before it is admitted, and the quote is stored and immutable whether you accept it
          explicitly or under an automatic-acceptance threshold you set.
        </p>
        <p>No invoice, balance or charge shown here would be real, so none is shown.</p>
      </NotYetAvailable>
    </>
  );
}

export function NotFoundPage() {
  return (
    <>
      <h1>Not found</h1>
      <p>That page is not here.</p>
      <p>
        <Link to="/">Back to the overview</Link>
      </p>
    </>
  );
}
