# redteam-hackbot-bench

`hackbench` benchmarks [redteam-hackbot](../../redteam-hackbot) (`~/projects/redteam-hackbot`). For each
target it runs fresh `/hunt --fresh '<prompt>'` hunts against the whole real product (raw material plus
`target.json`, nothing else), one hunt at a time. It records which known vulns a validated item proves,
how long that took, and what it cost. `README.md` is the operator guide. Keep it in step with the code.

## Where written output goes

- **Bench runs never go in this repo.** Run directories, instance workspaces, omp sessions, pane
  captures and `summary.md` / `summary.json` are written by `hackbench` under `work_root`
  (`~/hackbench-work/runs/<run-id>/`). Downloaded material lives in `cache_dir`
  (`~/.cache/hackbench`). Never copy them into the repo, and never point either setting inside it.
- **Analyses and write-ups** go in `./docs/` (create it if missing). This covers comparisons between
  runs, investigations of a hunt that missed or was mis-judged, and cost or time studies. Name a run
  analysis after its run id (`<run-id>-<slug>.md`). Name anything else with a short kebab-case name.
  Link to the run directory under `work_root`; do not paste its contents.
- **Research behind a target** (advisory analysis, version and patch verification, why a version
  was chosen) is ground truth.
  - It goes in the vuln's `targets/<id>/vulns/<vuln>.yaml` (`ground_truth`, `references`, `affected`).
  - A short summary goes in the target's `description` in `target.yaml`.
  - Longer notes go in `./docs/targets/<target-id>.md`.
  - Never put it anywhere a hunt can see: not in material, and not in a path listed under a target's
    `docs:` (those files are copied into the hunt's `vault/docs/`).
- **Plans** go in `./plans/` (see "Plans" below).
- **Diagrams** (HTML renderings of the bench flow, campaign timelines, cost charts) go in `./html/`.
- **Scratch work** (downloaded advisories, unpacked packages used to verify a version, throwaway
  scripts) goes in the session scratchpad, not the repo. Anything a conclusion rests on is recorded
  in the vuln spec or `./docs/` before the scratchpad is cleared.
- Never write `.md` files into the repo root or the current working directory just because the
  shell is there. The root holds only `README.md`, `bench.yaml` and the project's config files.
- When the destination folder already has files, follow its existing naming convention (look at the
  sibling files first).

## Layout

- `bench.yaml`: defaults (target selection, budgets, campaign, launcher, stop, detection, judge). A
  target's `budget:` and `campaign:` override them, and the CLI overrides both. `targets.include` /
  `targets.exclude` choose what runs (`-c` replaces include, `--exclude` adds); a pattern that matches
  nothing is an error.
- `hackbench/`: Python ≥ 3.9, stdlib plus PyYAML only. No other dependencies. Keep the syntax
  3.9-compatible: no `match`, no nested same-quote f-strings, `from __future__ import annotations`.
  - `config.py`: specs, lint, arch and OS selection.
  - `material.py`: fetch, verify, extract.
  - `runner.py`: one `HuntInstance`.
  - `campaign.py`: the per-target loop.
  - `cost.py`: omp session-file spend.
  - `items.py`: hackbot item files.
  - `match.py`: keywords and the LLM judge.
  - `launcher.py`: tmux / hunt host.
  - `report.py`: `summary.md` and `summary.json`.
  - `cli.py`: the CLI.
- `targets/<id>/`: `target.yaml` (strategy, prompt, budget, `os`, pinned per-arch `material`),
  `target.json` (copied verbatim into the workspace), and `vulns/<id>.yaml` (ground truth).
- `tests/`: unit tests, plus end-to-end campaigns driven by `tests/fixtures/fake_hunt.py` through a fake
  launcher, with a fake hackbot in `tests/fixtures/fake-hackbot/`.
- Runs go to `work_root` (default `~/hackbench-work`), never into this repo.

## Commands

```bash
python3 -m unittest discover -s tests     # must pass before any commit
bin/hackbench lint                        # every target spec
bin/hackbench check                       # host preflight (tmux, hunt host, case-sensitive work_root, …)
bin/hackbench run --dry-run               # the plan and the exact /hunt lines, runs nothing
```

A real run needs the Linux VM (`ssh raul@parallels-linux`): omp, tmux, the hackbot hunt host
(`hackbot-hunt.service`), the receipt service and Docker. macOS can run the tests, lint and dry runs only.

## Rules every change must keep

**The benchmark's numbers must stay honest.**

- **Ground truth never reaches a hunt.** `vulns/*.yaml`, judge prompts and judge sessions stay out of
  every workspace. The judge writes to a private temp dir and deletes it. `work_root` must stay outside
  this repo (`run` refuses otherwise). Never copy anything from `targets/*/vulns/` into material, docs or
  the `/hunt` line.
- **The hunt starts from the raw target only.** A workspace gets the `.omp` link, a new vault, the
  material, and `target.json`, and nothing else: no `CONTEXT.md` (so `/hunt` runs recon), no kb, and no
  earlier session.
- **Prompts are general.** A target's `prompt` names the goal ("hunt for an unauthenticated RCE in this
  project"), never the bug, component or file. It is one line with no single quotes.
- **Targets are whole products.** Ship the entire released artifact (package, release tarball, full
  source at the tag), never the vulnerable component cut out. The bench downloads it. Never commit
  material to this repo.
- **Material is pinned and verified.** Each download has a `sha256` from an authoritative source (a
  release digest or the vendor's package index). Each git checkout has a full 40-hex commit. Per-arch
  artifacts carry `arch:`. `target.json` keeps `researchMode: first-principles`, so a hunt cannot read
  advisories, changelogs, patches or VCS history.
- **Verify a version is vulnerable against the shipped artifact, not the advisory alone.** Advisories
  can be wrong: GitLab's says 19.5.0 is affected, yet the 19.5.0 package already ships the fix. Check the
  binary or the source at the exact tag, and record how it was checked in `target.yaml`'s `description`.
- **Ground truth is precise.** State the root cause with file and function, the fix, and the
  affected/fixed versions with sources. `not_this` lists sibling bugs from the same fix or release, so
  the judge cannot credit them. `match.all_of` keyword groups must separate each vuln from its siblings
  (add a test).
- **Platform scope is explicit.** A vuln that only exists on another OS gets `os: [<os>]`. It is listed
  but not scored against a target with a different `os:` (default `linux`). Example: Codex's PowerShell
  `--%` bug is Windows-only.
- **The judge is an Opus 5.5-grade model.** `judge.model` defaults to `anthropic/claude-opus-5-5` with
  `thinking: high`. Do not lower it to save cost: the judge alone decides what counts as found.
- **Spend is measured from omp's own records.** Cost comes from `usage.cost.total` on every assistant
  message and `model_usage` entry, in all session files of the instance, subagents included. Judge cost
  is reported separately and never mixed into hunt cost.

**A multi-hour unattended run must not die or leak.**

- **One hunt at a time.** The work-root lock stays. Concurrency is a later, planned feature: hunts are
  memory-heavy inside the VM.
- **Never touch the hunt host's services.** Never restart, stop or kill `hackbot-hunt.service`,
  `prltoolsd`, Docker, or the receipt service. On Linux, omp must start on the hunt host's tmux socket
  (hackbot's `/hunt` refuses elsewhere). So must the judge's one-shot omp: an omp outside the hunt host
  leaves a stray worker daemon that makes the next `/hunt` refuse.
- **Every wait is bounded.** Subprocesses have timeouts, and loops have deadlines (startup, `/hunt`
  start, budget, graceful stop, quiesce). A failure in one instance is recorded in its `result.json` and
  never crashes the run. Ctrl-C stops the current hunt, records it and exits; `--run-id` resumes.
- **Clean up after every instance.** Kill the tmux session and any leftover workspace processes, remove
  containers the instance created, delete extracted material unless `keep_material`, and keep reading
  session files during `quiesce_s` so spend after the stop shows up.
- **Extraction is safe and complete.** Every archive member is checked against escaping the
  destination: no absolute or `..` paths, no writes through symlinks, no setuid bits, no devices.
  Absolute symlinks in packages are rebased inside the destination. Hard links are created by the bench,
  not by tarfile in stream mode. A non-zero "skipped" count on real material is a bug to explain, not
  noise.
- **`work_root` is on case-sensitive VM-local disk,** never a Parallels shared folder (GitLab ships
  names that differ only in case).

## Adding a target

1. Pick the version from the vendor's data. Confirm it is vulnerable in the shipped artifact, and pin
   every download.
2. Write `target.yaml`. Use `strategy: campaign` with a general target-level `prompt`; `per-vuln` is
   only for when vulns need different prompts.
3. Write `target.json`: `artifactRoots` and `readOnly` point at the material dests, and `researchMode`
   is `first-principles`.
4. Write one `vulns/<id>.yaml` per known vuln, with `ground_truth`, `not_this`, `match.all_of`, and
   `os` when needed.
5. Add tests: the spec lints, the keywords route each vuln and miss its siblings, and the material is
   per-arch and pinned. Then run the real `fetch` plus `materialize` once and check the skipped count
   and that the vulnerable code or binary is present.
6. Update the targets table in `README.md`.

## Pull request titles

Follow the [Pull Request Naming Guide](https://github.com/adobe/react-spectrum/wiki/Pull-Request-Naming-Guide):
`type(scope): summary`. The merge commit carries the PR title, so the title is the change's history entry.

- `type` is one of: `feat` (a new feature), `fix` (a bug fix), `refactor` (no behaviour change), `docs`
  (documentation only), `test` (adds or fixes tests), `chore` (non-functional cleanup: formatting,
  typos, comments), `build` (packaging), `ci`, `bump` (a dependency or target version), `revert`.
- `scope` is optional: a noun naming the part of the codebase, for example `runner`, `campaign`,
  `material`, `judge`, `cost`, `report`, `launcher`, `cli`, `targets`, or a target id such as `gitlab`
  or `codex`. Never an issue or vuln ID.
- `summary` is lowercase and imperative, with no trailing period.
- Examples: `feat(targets): add gitlab ce 19.4.2 campaign`,
  `fix(material): create hard links outside tarfile stream mode`,
  `feat(config): skip vulns scoped to another os`.

## Plans

- A non-trivial feature (concurrency, a new material kind, a new strategy, a Windows target) starts with
  a plan in `./plans/`, named `[ID]-[NAME].md`. `ID` is two digits, zero-padded, and one more than the
  highest existing ID (starting at `01`). `NAME` is a short kebab-case name, for example
  `01-concurrent-hunts.md`.
- Write the plan before the code: the problem, the design and the alternatives rejected, the files to
  change, how it will be tested (fake-hunt tests plus a real VM run when it touches launch, stop or
  spend), and open questions. Commit it with the feature.
- Never renumber or reuse an ID. A dropped plan keeps its file and says it was dropped.
