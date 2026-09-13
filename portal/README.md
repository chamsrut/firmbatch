# The Firmbatch customer portal

The authenticated customer application (Milestone 3.2). It is **customer-only**: there is no
supplier, capacity, pool, bridge-budget, settlement, routing or certification surface here,
and no operator surface of any kind. The operator capacity agent is separate operator-side
software that runs in an operator's own cluster and is never a customer-portal feature
(roadmap "Internal and supplier surfaces"; target §17 invariant 11).

This is not the marketing site. `firmbatch.com` is a separate repository.

## Running it

Two processes, and they must be reached through **one origin**. The session cookie is
host-only and the CSRF cookie carries the `__Host-` prefix wherever it is `Secure`, which
forbids a `Domain` attribute — so a portal on one host could never read a cookie the API set
on another. Vite's dev server proxies `/v1` to the API, which is what makes them one origin.

Prerequisites: **Node 24 LTS** (`engine-strict` refuses anything older), PostgreSQL 16, and
the repository's Python environment.

```bash
# 1. Install the pinned dependencies, once.
cd portal && npm ci

# 2. The API, from the repository's PARENT directory. `firmbatch` is imported as a package.
cd "$(git rev-parse --show-toplevel)/.."
FIRMBATCH_ENV=test \
FIRMBATCH_DATABASE_URL=postgresql+psycopg://APP_ROLE:PASSWORD@127.0.0.1:5432/DATABASE \
FIRMBATCH_AUTHENTICATOR_DATABASE_URL=postgresql+psycopg://AUTH_ROLE:PASSWORD@127.0.0.1:5432/DATABASE \
FIRMBATCH_API_ALLOWED_ORIGINS=http://127.0.0.1:5173 \
FIRMBATCH_API_COOKIE_SECURE=false \
  python3 -m firmbatch.control_plane.api --port 8081

# 3. The portal, in another terminal.
cd firmbatch/portal && npm run dev
```

Then open <http://127.0.0.1:5173>.

`FIRMBATCH_API_ALLOWED_ORIGINS` must name the **portal's** origin: the API checks `Origin`
against that list on every cookie-authenticated mutation, and a browser sends `Origin` on
same-origin unsafe methods too. `FIRMBATCH_API_COOKIE_SECURE=false` is accepted only with
`FIRMBATCH_ENV=test`, and is what lets the cookies work over plain http locally; it also
selects the unprefixed `fb_csrf` name, because a browser rejects a `__Host-` cookie that is
not `Secure`.

**No email is sent.** In the test environment the delivery adapter captures messages in
memory, so a verification or recovery link never leaves the process. To complete those flows
locally, read the token from the API process or drive the account through
`control_plane/tests/identity_helpers.py`.

## Checking it

```bash
cd portal && npm run verify
```

That is `biome ci . && tsc --noEmit && vitest run && vite build` — format, lint, types, tests
and a production build — and it is exactly what `./scripts/verify-repository.sh` runs as its
**customer portal** gate. The gate fails, rather than skipping, when `npm` or
`portal/node_modules` is absent: an unrun test suite reports the same green as a passing one.

Individually: `npm run lint`, `npm run typecheck`, `npm test`, `npm run build`, and
`npm run format` to apply formatting (`biome ci` never writes).

## How it is built

TypeScript, Vite and React, with Vitest and React Testing Library. **React and ReactDOM are
the only runtime packages**; everything else in `package.json` is a development tool — Vite
with its React plugin, TypeScript, Biome, Vitest with jsdom, Testing Library and the type
packages — and `package.json` is the authority for the exact list. The router, the API
client and the interface components are in `src/` and are about a thousand lines in total.
ADR 0010 records why.

| Path | What |
| --- | --- |
| `src/api/client.ts` | The one place this portal talks to the API: same-origin paths only, CSRF on every cookie-authenticated mutation, bounded bodies, neutral errors |
| `src/api/endpoints.ts` | Every call the portal can make, named once — a grep of this file is the complete customer surface |
| `src/lib/csrf.ts` | Reading the CSRF cookie, and why it is a cookie |
| `src/lib/redirect.ts` | What a `next=` destination is allowed to be |
| `src/lib/one-time-token.ts` | Verification, recovery and invitation tokens: out of the URL once, held in memory, used at most once at a time |
| `src/lib/requests.ts` | A ticket for every page request, so only the newest load publishes and nothing lands after the page, session or workspace moved on; and one keyed single flight for page reads |
| `src/auth/session.tsx` | Who is signed in, what the *server* says they may do, the one sign-out operation (single-flight, fenced to the session it began under, bounded), and the lease every request carries so that no answer about a replaced session is ever applied |
| `src/ui/` | The shell and the shared components |
| `src/routes/` | The twenty pages, grouped by journey into seven modules: nineteen registered routes and the not-found fallback (`App.tsx` holds the route tables) |
| `tests/` | 392 tests: journeys, permissions, secrets, redirects (including destinations that are paths by every syntactic rule and protocol-relative once the parser has normalised them), accessibility, one-time tokens and mount-time reads under `StrictMode`, one sign-out operation fenced to its session and settled by one bounded validity read, the session lease on every route, the replacement barrier, ordered and coherent refreshes, the binding-first workspace switch, the workspace every request was made for, the lifecycle of a page's requests |

Nothing is written to `localStorage` or `sessionStorage` — the test setup makes any access
throw, and `tests/storage.test.ts` scans the source as well.
