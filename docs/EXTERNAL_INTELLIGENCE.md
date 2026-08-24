# External intelligence boundary

Status: phase 2 implemented on 2026-08-24. This document records a dated
provider snapshot; it is not a permanent availability claim.

## Decision

BELIEF treats public databases as untrusted, context-only intelligence. Their
records cannot become `Finding`, `AuditCase`, `ValidationResult`, validation
proof, or reportability score input. Duplicate CVE identifiers across providers
do not establish independent corroboration because databases may mirror the
same upstream advisory.

BELIEF supports strict parsing and opt-in bounded retrieval for:

- OSV `POST https://api.osv.dev/v1/query`;
- CISA KEV's full JSON catalog;
- NVD CVE API 2.0 `GET https://services.nvd.nist.gov/rest/json/cves/2.0`;
- GitHub Global Security Advisories `GET https://api.github.com/advisories`,
  pinned to REST contract `2026-03-10`.

The live transport permits only those exact HTTPS endpoints, refuses redirects,
requires an explicit timeout, byte limit, and user agent, and returns typed
failures. Parsers preserve every source occurrence, bind records to the exact
query and response SHA-256 digests, and reject malformed, ambiguous, paginated,
or count-inconsistent responses. Valid empty results remain distinguishable
from transport and parse failures.

NVD and GitHub use structured endpoint policies rather than caller-provided
URLs. Scheme, host, port, path, method, query keys, query cardinality, and
canonical encoding are checked before a request can be created. Redirects and
final-URL changes remain refused. NVD queries require either 1-100 `cveIds` or
a closed last-modified window of at most 120 days. GitHub queries require a
GHSA ID, CVE ID, or closed modified-date window; BELIEF additionally caps that
window at 31 days and a page at 100 records.

Optional NVD API keys and GitHub bearer tokens are isolated in non-represented
credential headers. They are excluded from request URLs, equality, repr output,
query digests, selected response-header digests, parsed records, and serialized
page envelopes.

## Page provenance

NVD and GitHub parsers return a companion
`belief.external_intelligence_page.v1` envelope around the existing immutable
batch. The envelope retains:

- separate collection-query and exact page-query SHA-256 digests;
- the exact request URL and raw-response digest;
- a safe, allowlisted response-header snapshot and its digest;
- offset or cursor position, next position, page completeness, and collection
  completeness without claiming provider snapshot isolation;
- documented rate-limit policy and any observed limit, remaining, used, reset,
  retry, and resource fields;
- the selected API contract and provider response timestamp when supplied.

For GitHub, BELIEF validates a `rel="next"` URL but never follows it directly:
the URL must retain the exact GitHub origin, path, collection filters, and page
size, after which only the bounded cursor is retained and a new request is
rebuilt. An interrupted or inconsistent page is an explicit parse failure, not
an empty result.

Because parser input does not carry a trusted credential class, NVD/GitHub
pages do not guess a policy limit from a caller-provided authentication flag.
`policy_limit` and `policy_window_seconds` remain null; safe response headers
retain the provider-observed quota state. This avoids mislabeling GitHub App,
Actions, Enterprise, user-token, or unauthenticated limits.

NVD timestamps omit an explicit `Z` in API responses even though NVD documents
response datetimes as zero-offset UTC. Only the NVD adapter applies that
provider-specific normalization; the generic timestamp parser still requires
an explicit offset.

## License and attribution

- NVD is recorded as provider-documented US public-domain material with the
  required non-endorsement notice and Terms of Use URL. Modified NVD content
  must not be represented as NVD-authored content.
- GitHub Advisory Database records are recorded as `CC-BY-4.0` with attribution
  to `https://github.com/advisories`.

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
  [NVD API guidance](https://nvd.nist.gov/developers/start-here), plus the
  [NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use)
- [GitHub global advisory API](https://docs.github.com/en/rest/security-advisories/global-advisories),
  [REST API versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions),
  and [Advisory Database license terms](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features)
- [OpenAlex API documentation](https://docs.openalex.org/)
- [Crossref REST API](https://www.crossref.org/documentation/retrieve-metadata/rest-api/)

## Remaining provider work

OpenAlex and Crossref may support literature discovery, not vulnerability
validation. Cursor checkpoints must be durable before adding Crossref bulk
collection; service maintenance can invalidate an in-flight cursor. No external
provider may raise reportability without a separately verified
`belief.validation_proof.v1` record bound to the local engagement, target,
attempt, result, oracle, and evidence digests.
