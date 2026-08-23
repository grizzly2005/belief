# External intelligence boundary

Status: phase 1 implemented on 2026-08-23. This document records a dated
provider snapshot; it is not a permanent availability claim.

## Decision

BELIEF treats public databases as untrusted, context-only intelligence. Their
records cannot become `Finding`, `AuditCase`, `ValidationResult`, validation
proof, or reportability score input. Duplicate CVE identifiers across providers
do not establish independent corroboration because databases may mirror the
same upstream advisory.

Phase 1 supports strict parsing and opt-in bounded retrieval for:

- OSV `POST https://api.osv.dev/v1/query`;
- CISA KEV's full JSON catalog.

The live transport permits only those exact HTTPS endpoints, refuses redirects,
requires an explicit timeout, byte limit, and user agent, and returns typed
failures. Parsers preserve every source occurrence, bind records to the exact
query and response SHA-256 digests, and reject malformed, ambiguous, paginated,
or count-inconsistent responses. Valid empty results remain distinguishable
from transport and parse failures.

## Live source snapshot

Read-only probes on 2026-08-23 returned HTTP 200 from NVD, CISA KEV, OSV,
GitHub Global Security Advisories, OpenAlex, and Crossref.

Observed reference queries:

- NVD returned one analyzed entry for CVE-2021-44228, last modified
  `2026-08-11T19:33:44.513`.
- CISA KEV reported catalog version `2026.08.21`, release timestamp
  `2026-08-21T17:46:43.6019Z`, and 1,674 entries.
- OSV returned four advisory identifiers for PyPI package `pyyaml` version
  `5.3`.
- GitHub returned reviewed advisory `GHSA-jfh8-c2jp-5v3q` for
  CVE-2021-44228.

Primary provider references:

- [OSV API](https://google.github.io/osv.dev/api/) and
  [OSV data/license notes](https://google.github.io/osv.dev/data/)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  [JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
  and [CC0 license](https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)
- [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) and
  [NVD API guidance](https://nvd.nist.gov/developers/start-here)
- [GitHub global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [OpenAlex API documentation](https://docs.openalex.org/)
- [Crossref REST API](https://www.crossref.org/documentation/retrieve-metadata/rest-api/)

## Deferred adapters

NVD and GitHub advisories are the next security-context candidates. Their
adapters must retain provider revisions, pagination cursors, rate-limit state,
license/attribution metadata, query digests, and raw-response digests under the
same context-only rule.

OpenAlex and Crossref may support literature discovery, not vulnerability
validation. Cursor checkpoints must be durable before adding Crossref bulk
collection; service maintenance can invalidate an in-flight cursor. No external
provider may raise reportability without a separately verified
`belief.validation_proof.v1` record bound to the local engagement, target,
attempt, result, oracle, and evidence digests.
