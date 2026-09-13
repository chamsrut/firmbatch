/**
 * Refuse to run the portal's checks on a Node older than this project requires.
 *
 * `engine-strict=true` in `.npmrc` makes `npm ci` refuse an older runtime, which covers
 * installing. It does **not** cover `npm run`: a `node_modules` installed under Node 24 will
 * happily be *used* by Node 20, and the portal gate would then be reporting a pass from a
 * runtime nobody chose. This is what makes "Node 24 LTS, locally and in CI" true at the
 * moment the checks actually execute.
 *
 * It lives here rather than in `scripts/verify-repository.sh` deliberately: that file is
 * protected by AGENTS.md, and the change approved for it was one gate and its required-file
 * entries. A version assertion is the portal's own business.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const manifest = JSON.parse(
  readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"),
);

const required = manifest.engines?.node ?? "";
const minimum = Number.parseInt(required.replace(/[^0-9]/g, ""), 10);
const actual = Number.parseInt(process.versions.node.split(".")[0], 10);

if (!Number.isFinite(minimum)) {
  process.stderr.write("portal/package.json does not declare engines.node\n");
  process.exit(1);
}

if (actual < minimum) {
  process.stderr.write(
    `The portal requires Node ${required} and this is Node ${process.versions.node}.\n` +
      "Install Node 24 LTS and put it first on PATH, then run the checks again.\n" +
      "This is not skipped: checks that ran on an unintended runtime prove nothing about\n" +
      "the one the project targets.\n",
  );
  process.exit(1);
}
