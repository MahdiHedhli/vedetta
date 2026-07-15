# Repository data sanitation

Vedetta's public repository contains synthetic fixtures only. Real network
captures, event exports, databases, IP/MAC inventories, local hostnames, and
credentials must remain outside Git.

## Safe fixture values

Use these reserved values when a test needs network-shaped data:

- IPv4: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24`)
- IPv6: RFC 3849 (`2001:db8::/32`)
- MAC: the RFC 7042 documentation block (`00:00:5E:00:53:00/24`)
- DNS names: `.example`, or an unmistakable `placeholder` name for a local-name rejection test

Standard mDNS/SSDP multicast addresses are allowed where a protocol fixture
needs them. Do not copy a real artifact and redact only the fields you notice;
construct the fixture from synthetic values instead.

## Local lab storage

Keep private inputs under `.local/`, `lab/`, or `labs/`. These paths and common
capture/database/export/scan/backup formats are ignored, including plural forms
and arbitrary named variants such as `lab-prod/` or `capture-old/`. Security- or
operator-local directories are also ignored and unconditionally refused when
force-added: root `internal`/`private` families, `logs`, `.aws`, `.gcp`,
`.terraform`, `.docker`, agent metadata, and analysis/agent/scratch families
(including their dot-, hyphen-, and underscore-named variants).
This path policy is intentionally narrower than a build-cache ban: ordinary
dependency and build caches are not classified as private evidence merely by
their directory names. All dotenv-shaped paths are ignored case-independently.
The already-tracked root `.env.example` remains usable; if a new template is
force-added, the sanitation checker permits only the exact lowercase
`.env.example` basename and still inspects its contents.

Before opening a PR that changes fixtures or embedded data, run:

```bash
bash scripts/check-repo-sanitization.sh
bash scripts/tests/repo-sanitization-test.sh
bash scripts/tests/deploy-sanitation-test.sh
bash scripts/tests/trusted-pr-sanitation-test.sh
```

The default command inspects the staged Git index: run `git add` first when
checking a proposed commit. To inspect every tree in a commit range (including
a file added in one commit and deleted in the next), use:

```bash
bash scripts/check-repo-sanitization.sh --history-range origin/main..HEAD
```

The trusted PR inspection is
`.github/workflows/trusted-repository-sanitation.yml`. It uses
`pull_request_target` so the workflow definition comes from the trusted default
branch, then checks out the runner, selector, and checker from the exact event
base SHA rather than the candidate merge commit. A contents-read workflow token
is passed only to that base-owned runner and applied as a URL-scoped HTTP header
for its single Git fetch; it is not persisted in the checkout, remote URL, or
repository configuration. The read-only runner fetches `refs/pull/<number>/head`
and `/merge` into
a temporary inspection-only Git repository, verifies the event OIDs and merge
parents, requires the event base to remain the current fetched base tip, prints
all three verified OIDs, loads the proposed merge tree into a Git index, and
scans that index plus every `base..head` commit. Candidate files are never
checked out, sourced, imported, built, or otherwise executed.

On this user-owned repository, treat the resulting `trusted-data-scan` run as an
exact-head owner merge gate, not as an enforceable required status. A
`pull_request_target` job is associated with the base SHA, while a status posted
by its ordinary `GITHUB_TOKEN` could be spoofed by another same-repository
workflow using the same GitHub Actions identity. Fully automated enforcement
requires either an organization-level required-workflow rule or a dedicated
GitHub App status identity unavailable to candidate workflows. Until then, the
owner verifies the workflow name, event, successful conclusion, current PR head
and merge OIDs, and that the logged base OID still equals the current `main` tip
immediately before merging. The workflow remains read-only and does not
explicitly post a custom commit status or check; GitHub Actions still creates
its normal workflow check run. Gitleaks remains the separate `secret-scan`
check.

Ordinary CI also runs candidate copies of the three regression suites to catch
accidental development regressions; that read-only job is explicitly
non-authoritative because candidate code can edit its own tests. The privileged
workflow intentionally does not run regression suites: keeping its executable
surface to the protected runner, selector, and isolated-mode checker prevents a
clean PR from poisoning an unprotected test dependency for the next run.

PR #89 is the one-time bootstrap for this design because its base branch does
not yet contain the checker or trusted workflow. It therefore requires the
recorded exact-head adversarial reviews and owner merge. Immediately after that
merge, validate the boundary with a canary PR that both adds a synthetic
private-address fixture and no-ops its candidate checker; confirm the base-owned
`trusted-data-scan` run fails, then confirm a clean canary passes. Keep the
exact-run owner gate for every later merge unless one of the independently
enforceable status mechanisms above is installed. The trusted runner never
falls back to candidate policy when the base implementation is absent.

A recreated default branch with no trustworthy predecessor is scanned from its
complete reachable history. The dedicated
`.github/workflows/repository-sanitation.yml` workflow and
`scripts/select-sanitation-range.sh` provide best-effort post-receive detection
for branch/tag pushes whose pushed ref contains the intact workflow, helper, and
checker. An old ref without them, or a ref that alters them, is not made trusted
by ref-owned GitHub Actions. Actions also cannot stop an unprotected ref becoming
visible before a push workflow completes, so protected pull requests plus the
manual exact-run owner gate are the preventive control for the public default
branch.

The deployment helper fetches the actual push destination, captures and scans an
immutable commit plus all unpublished history, and pushes that exact SHA under an
expected-tip lease. The deployment checkout must be clean, on the expected
branch, and able to fast-forward to that same SHA. It passes
`VEDETTA_EXPECTED_HEAD` to an updater loaded from that commit's immutable Git
blob rather than the mutable worktree path. Its sourced port-configuration
helper comes from the same commit on a separate descriptor, while operator stdin
remains available for service prompts. An independent launcher rejects checkout
movement before either reviewed blob runs. Pinned mode performs no pull/rebase
or `go mod tidy`, rejects ignored or untracked build inputs, and re-verifies the
exact checkout at build and restart boundaries. Trust decisions bind Git to the
canonical deployment directory, ignore replacement objects and repository-local
exclude metadata, disable hooks/fsmonitor and configured clean/smudge filters,
and raw-hash every tracked regular file without filters against the exact index
and commit. Before the local publisher runs `ls-remote`, fetch, or push, it
requires the captured push destination to be an explicit absolute/file, HTTP(S),
SSH, or scp-style location and restricts Git to those native protocols. This
also rejects any URL rewrite that can still apply to the captured destination,
preventing an arbitrary Git remote-helper launch or a push-only destination
split, and ignores an inherited Git helper path. Remote selection, rewrite
inspection, and transport ignore the config-command-only `GIT_CONFIG` override
so they share one effective configuration, while normal shared Git
configuration remains available. Local SSH publication pins Git to an external,
absolute-path `ssh` resolved from the operator's PATH in non-interactive mode;
ambient or repository functions, `sshCommand`, and askpass overrides are
ignored. Normal user and system SSH
configuration, keys, agents, host aliases, ProxyJump, and ProxyCommand remain
available. Authentication must therefore already work without a prompt. Local
object reads disable lazy fetching. Each remote pinned Git
boundary also discards inherited Git executor,
configuration, object-store, protocol, SSH, proxy, credential, pager, and editor
environment variables; disables lazy object fetching and automatic maintenance;
denies `git://` and external transports; permits only explicit absolute/file,
HTTP(S), SSH, or scp-style upstream locations; and suppresses signature,
autostash, hook, and external-diff execution. Repository-local includes,
alternates, grafts, partial/promisor stores, bundle URIs, URL rewrites, custom
protocol permissions or upload-pack commands, merge drivers/options, credential
helpers, and other command-bearing Git settings fail closed before object
access. Pinned deployment
requires a normal non-linked `.git` directory with local regular control files
and object storage, and does not support tracked symlinks or gitlinks. The pinned
native sensor build uses `-buildvcs=false`, preventing Go from invoking mutable
repository Git again for redundant VCS stamping. Before deployment side effects,
pinned mode materializes the reviewed commit into a root-owned, non-writable
snapshot and verifies its complete file set, modes, and blob hashes. Compose
reads its base graph and every build context from that snapshot while retaining
the installation directory for project identity and root `.env` interpolation.
It builds the four default services and starts those exact images with
`--no-build`; an ignored `docker-compose.override.yml` or `COMPOSE_FILE` cannot
replace the reviewed graph. The sensor and service templates also come from the
snapshot. Its binary is built into root-only storage, copied to a privileged
same-directory temporary file, and atomically renamed into place. Pinned sensor
installation requires every physical ancestor of `/usr/local/bin` to be
root-owned, non-symlinked, and non-writable by the deployment account; it fails
closed rather than changing ownership on Homebrew-style installations. Pinned
mode removes inherited macOS ACLs from its private snapshot and staging file,
then verifies effective non-writability as the deployment account before either
build input or binary is consumed. The root
`.env`, Docker daemon, host toolchain, and upstream base images remain external
operator/supply-chain inputs, so this is an exact-tracked-code guarantee rather
than hermetic runtime reproducibility. Standalone
`update-all.sh` retains normal pull, Compose override discovery, and update
behavior.

These checks close accidental checkout movement and unreviewed Git-metadata
bypasses at each verification boundary. Once the protected snapshot exists, a
process confined to the ordinary deployment account can swap and restore tracked
worktree bytes during Docker or Go reads without changing the built inputs or
installed sensor artifact. The root account, Git object database, Docker daemon,
PATH-resolved host toolchain, and local Git configuration and hooks used while
the commit is verified and materialized remain trusted operator boundaries; this
includes configured filters, fsmonitor, signing, and maintenance programs. The
checks also do not claim to defeat a race in trusted local Git configuration
inside one validation or transport call. Configured credential helpers and HTTP
proxy, plus user/system OpenSSH configuration (including any commands it
launches), are trusted as well. The publication transport separately overrides
the SSH, askpass, protocol, and helper-selection controls described above.

The sanitation check rejects risky tracked file types and archives everywhere,
including encrypted/wrapped archive names, forced editor-backup (`*~`) files,
and complete LF or CRLF Git LFS pointer records whose real contents would
otherwise be absent from CI. Every regular tracked blob rejects NUL bytes so a
non-executable sourced helper cannot hide shell content behind an opaque binary
diff. The only exceptions are the exact path-and-SHA-256-bound, non-executable
media blobs already reviewed in this policy. New or changed opaque media requires
an explicit gate-maintenance review; a candidate-edited path, extension, format
signature, or manifest cannot approve itself. Near-pointer prose is not mistaken
for an LFS record. All tracked
symlinks and gitlinks/submodules are rejected before content
classification, including in history scans, because either can hide data or
publish a local target path. It content-scans every blob under the declared
corpus, data/dataset, fixture, sample/demo-data, test-data, and inventory
families, including their listed singular/plural aliases and numeric-leading
hyphen/underscore version variants, plus arbitrary named inventory variants,
regardless of file extension. Reviewed SQL migrations and embedded
threat-network data are scanned too. Two exact corpus test files are exempt because
they intentionally contain unsafe strings to prove the separate publication
privacy gate. The operational sanitation regression is exempt for the same
reason. The base-owned trusted runner compares all three exempt blobs—and the
workflow, runner, checker, selector, and policy regression suite—with the base
commit in every introduced commit plus the proposed merge tree. Neither a
temporary exempt-file leak nor a clean trust-root no-op can land through an
ordinary PR. Changing a protected policy path requires an explicitly reviewed
gate-maintenance bootstrap. Direct, regular files with the exact lowercase
`.go` suffix in
`telemetry/internal/export/` are treated as application source because `export`
is that package's name; nested
files, non-source blobs, and symlinks under it remain forbidden. Within
data-shaped paths, production corpus code, new tests or generators, and
README/Markdown files are scanned regardless of extension. Operational
shell/PowerShell/service/config files and `.env.example` are scanned as well.
The documented fresh-install CIDR in `.env.example` is an explicit
product-default allowlist, not an observed network value.

The scan recognizes identifiers in both contents and tracked paths: IPv4/IPv6
addresses, common MAC encodings (including Cisco-dot, compact, contextual
`mac`/`macAddress`/`macAddr`, source/device-MAC, `bssid`, `hwAddr`, and `0x`
forms, plus Nmap XML values), and structured/local hostname
fields such as `.local` and `.home.arpa`. Private-suffix names are tokenized as
complete Unicode labels, so non-ASCII or emoji device names and instance-prefixed
mDNS names cannot hide behind a safe service suffix. The three IDNA-recognized
dot variants are normalized in both contents and paths, so a fullwidth or
ideographic dot cannot disguise a private suffix. JSON escapes and XML numeric
entities are decoded before inspection. Relational
type/value pairs (`attribute`/`value`, device identity/address pairs, detector
observables, and indicator pairs) retain their row-level IP, MAC, hostname,
or version type instead of becoming untyped strings. JSON is strict, rejects
normalized duplicate keys and identity-bearing container values, and permits
line-delimited JSON only in the existing reviewed UniFi expected-output directory;
its value budget applies to the whole file, not separately to each line. CSV/TSV
parsing retains quoted multiline records and rejects ambiguous shapes or disguised
alternate delimiters. Inventory, fingerprint, and device-data JSON/CSV/TXT files,
including dot-separated names such as `device.inventory.json`,
`device.fingerprints.csv`, and `device.data.txt`, must use an explicit normalized
schema rather than hostname-keyed maps or transposed headers. In inventory paths,
nested `name` fields and identifier-shaped notes/comments receive hostname review
even when the containing filename itself is generic. Structured keys are
normalized across acronym/camelCase, kebab-case, dotted, and display-name forms
before typing and duplicate detection. Lightweight YAML list records, TOML/INI
sections, and blank-line-separated text records have separate scopes; canonical
duplicates within one scope and ambiguous repeated sections fail closed. An exact
64-hex structured key is recognized as a SHA-256 digest, while shorter, embedded,
or explicitly MAC-labeled keys remain subject to compact-MAC checks. The embedded
public allowlist accepts only unique, lowercase, multi-label public-domain syntax.
Percent/underscore pseudo-patterns are rejected from ordinary typed domain fields;
the SNR seed's fixed, reviewed SQL cleanup patterns are the narrow exception.
The reviewed UniFi logs have a bounded RFC 3164/CEF/DHCP parser that permits only
synthetic header and device hostnames, including camel/acronym host-field aliases.
Simple YAML/TOML/INI/text identity fields and relational pairs are mapped;
multiline/container syntax in a typed field
fails closed rather than being guessed.
Structured firmware/software version fields may contain realistic vendor-dotted
versions; direct and relational type/value pairs receive the same occurrence-bound
handling in JSON, CSV/TSV, XML, YAML, TOML, INI, and reviewed text. The exemption
is tied to that exact field occurrence, and an obvious private address or a
prefix-preserving invalid RFC1918/link-local dotted quad remains forbidden even in
a version field. Version-span containment uses a sorted logarithmic lookup so a
large, bounded table cannot turn inspection quadratic. Reviewed SQL must use
an intentionally restricted, reviewable grammar. The SQL gate is an
accidental-disclosure control, not a verifier for arbitrary SQLite programs.
Five unchanged legacy migrations that perform structural identity copies are
accepted only when both their paths and SHA-256 digests match the policy; changing
even one byte subjects the migration to the forward-only grammar. New migrations
may write identity or relational value fields only from direct static literals,
`NULL`, or empty values. Parameters, constructed or tuple writes, identity-bearing
`INSERT ... SELECT`, generated columns, non-structural typed query outputs, and
literal-bearing typed predicates are rejected. The current database-health report
is also digest-bound; any edit is evaluated by the read-only report grammar. The
SNR seed script is limited to static fixture rows and fixed cleanup/report
statements. This gate does not trace arbitrary cross-statement SQL
dataflow, schema renames, or whitespace-only natural-language comments; manual
review remains required for every SQL change. Raw identifier scanning, lexical
validation, and resource ceilings still apply to every reviewed SQL file. XML uses
a bounded strict grammar:
numeric and predefined entities are decoded, while DTD/entity declarations,
CDATA, comments, processing instructions beyond the XML declaration, namespaces,
and malformed attributes/nesting are refused. Database rollback journals,
opaque archives, and non-UTF-8 data are refused. Every regular tracked blob must
be no larger than 8 MiB. JSON is additionally capped at 1 MiB,
CSV/TSV/XML at 2 MiB, and SQL at 256 KiB, with independent field, statement,
operator, nesting, logical-line, and file-wide value-count ceilings so untrusted
pull requests cannot exhaust CI parser memory. Logical-line accounting recognizes
all separators handled by the structured parsers, including CR, NEL, and Unicode
line separators. Failure messages redact rejected values;
an identifier-bearing path is represented by a non-reversible per-run ordinal so
a public Actions log does not become a second disclosure. To map that ordinal to
a path locally, rerun the same command with `--show-paths`; never use that flag in
public CI. Compact MAC-like values are checked in decoded structured scalars and
risk-shaped paths (with UUIDs and exact SHA-256 map keys recognized separately),
so use a full content hash when naming corpus blobs. Device/source hostname fields
require reserved
synthetic names; public-domain indicator fields may retain genuine public IOCs.

Ordinary application source and narrative documentation outside data-shaped paths
are not blanket-scanned for private-range literals: network-security code needs
such constants and negative privacy tests deliberately contain them. Gitleaks,
review, and the stricter corpus/config/export controls remain required; do not
treat this guard as proof that an arbitrary source-code string is synthetic.

This is a forward-looking gate; it does not rewrite already-published Git
history. If real data is ever committed, stop distribution, rotate any affected
credentials, and follow the repository's security incident process before a
coordinated history cleanup.
