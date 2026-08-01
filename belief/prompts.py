"""
BELIEF — Prompt templates (v2).

Key v2 changes:
1. **Predicate DSL is now mandatory** in EXTRACT_BELIEFS_PROMPT. The LLM
   gets a closed list of operators it must use. Predicates outside that
   DSL get logic_type='semantic' and skip Z3 instead of being mistranslated.
2. **Few-shot examples redrawn** from real CVE patterns (path traversal,
   SQLi via string concat, missing nullity check, integer underflow).
3. **REPAIR prompts** added: PREDICATE_REPAIR_PROMPT and JSON_REPAIR_PROMPT
   for the Z3 repair loop and the JSON parse fallback respectively.
4. **GROUNDING block** is now a parametric template that the extractor
   fills with KB-matched taint sources/sinks before sending.
"""

# ─────────────────────────────────────────────
#  System prompt — applies to all extraction calls
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are BELIEF, a specialized system for extracting implicit software beliefs.

A "belief" is something the developer assumed to be true when writing the code,
without explicitly verifying it. Every function, every variable, every control
flow decision encodes beliefs about the state of the world.

Your job is to make these invisible beliefs visible and FORMAL.

Hard rules:
- You output ONLY valid JSON. No markdown fences. No preamble. No commentary.
- Predicates must reference variables that LITERALLY appear in the source code.
- Every anchor_line must be inside the function's [line_start, line_end] range.
- If you cannot ground a belief in concrete code, do NOT emit it.\
"""

# ─────────────────────────────────────────────
#  The Predicate DSL — closed grammar
# ─────────────────────────────────────────────

PREDICATE_DSL = """\
## Predicate DSL (use ONLY these operators when logic_type='fol')

Operators:
  Comparison:   <, <=, >, >=, ==, !=
  Membership:   in, not in
  Boolean:      and, or, not, implies
  Functions:    len(x), type(x), isinstance(x, T)
  Constants:    None, True, False, integer literals, "string" literals,
                {a, b, c} for finite sets

Examples of VALID predicates:
  len(input) <= 1024
  user.role == "admin"
  config.timeout > 0
  request.path not in {"/admin", "/internal"}
  payload != None and len(payload) > 0
  status_code >= 200 and status_code < 300
  isinstance(value, str) implies len(value) > 0

Examples of INVALID predicates (do NOT produce these as 'fol'):
  "the input is sanitized"             ← vague, set logic_type='semantic'
  user_input.is_safe()                 ← method call, set logic_type='semantic'
  the loop terminates                  ← temporal, set logic_type='temporal'
  data flows from request to db        ← info_flow, set logic_type='info_flow'

If the property does NOT fit the DSL, set logic_type to one of:
  semantic    — natural language predicate, will use LLM verifier
  temporal    — about behavior over time
  info_flow   — about data propagation
  behavioral  — about functional properties (idempotent, commutative)
  probabilistic — about likelihoods\
"""

# ─────────────────────────────────────────────
#  Phase 1: Extract beliefs from a single frontier
# ─────────────────────────────────────────────

EXTRACT_BELIEFS_PROMPT = """\
Analyze this code and extract ALL implicit beliefs the developer holds.

## Source Code
```
{code}
```

## Context
- File: {file_path}
- Function/Class: {function_name}
- Module: {module_name}
- Callers: {callers}
- Documentation: {documentation}
- Test coverage: {test_info}
{grounding_block}
{dsl_block}

## Output Format
Return a JSON array of belief objects. Each belief has:

{{
  "predicate": {{
    "expression": "<DSL-conformant assertion, e.g. 'len(input) <= 1024'>",
    "variables": ["<identifiers referenced — must appear in the code>"],
    "anchor_lines": [<line numbers within scope where evidence exists>],
    "natural_language": "<one-sentence explanation>"
  }},
  "scope": {{
    "function_name": "<name or null>",
    "class_name": "<name or null>",
    "line_start": <int>,
    "line_end": <int>
  }},
  "justification": "<C1|C2|C3|C4|C5|C6>",
  "dependencies": ["<predicate expressions this belief depends on>"],
  "epistemic_status": "<belief|hope|unknown>",
  "logic_type": "<fol|temporal|info_flow|behavioral|probabilistic|semantic>",
  "confidence_score": <0.0 to 1.0>
}}

## Justification Categories
- C1: Mechanically proven by a replayable proof artifact bound to this exact source
- C2: Property verified by an identified static-analysis result
- C3: Enforced by an explicit runtime guard in this function
- C4: Assumed by known callers but not guarded in this function
- C5: Stated in a comment, docstring, specification, or documentation
- C6: Unsupported assumption, heuristic inference, or opaque external claim

## Rules
1. Be SPECIFIC. Not "input is valid" but "len(user_input) <= 1024".
2. Every variable in `predicate.variables` MUST appear textually in the code.
3. Every anchor_line MUST be inside [scope.line_start, scope.line_end].
4. If logic_type='fol', `predicate.expression` MUST conform to the DSL above.
5. If you can't fit it in the DSL, use logic_type='semantic' instead — do NOT
   force-fit semantic properties into bad pseudo-Z3 syntax.
6. Never emit C1 or C2: extraction has no proof/static-result artifact. Use C3
   only for an explicit guard. If `justification='C5'`, the predicate keyword must be findable
   in the docstring or comments.
7. Look for beliefs about: types, sizes, nullity, concurrency, trust,
   encoding, error handling, resource availability, timing, ordering.

## Examples

[
  {{
    "predicate": {{
      "expression": "len(user_input) <= 1024",
      "variables": ["user_input"],
      "anchor_lines": [42],
      "natural_language": "The developer assumes user input is at most 1024 characters"
    }},
    "scope": {{
      "function_name": "parse_request",
      "class_name": "RequestHandler",
      "line_start": 38,
      "line_end": 55
    }},
    "justification": "C6",
    "dependencies": [],
    "epistemic_status": "belief",
    "logic_type": "fol",
    "confidence_score": 0.85
  }},
  {{
    "predicate": {{
      "expression": "db_connection != None",
      "variables": ["db_connection"],
      "anchor_lines": [61, 63],
      "natural_language": "The developer assumes the database connection is non-null"
    }},
    "scope": {{
      "function_name": "fetch_user",
      "class_name": "UserService",
      "line_start": 58,
      "line_end": 72
    }},
    "justification": "C6",
    "dependencies": [],
    "epistemic_status": "hope",
    "logic_type": "fol",
    "confidence_score": 0.9
  }},
  {{
    "predicate": {{
      "expression": "user_input is sanitized before sql execution",
      "variables": ["user_input"],
      "anchor_lines": [88],
      "natural_language": "The developer assumes the SQL string was escaped upstream"
    }},
    "scope": {{
      "function_name": "run_query",
      "class_name": null,
      "line_start": 85,
      "line_end": 92
    }},
    "justification": "C6",
    "dependencies": [],
    "epistemic_status": "hope",
    "logic_type": "semantic",
    "confidence_score": 0.7
  }}
]

Now extract ALL beliefs from the provided code. Output ONLY the JSON array.\
"""


# ─────────────────────────────────────────────
#  Z3 Repair Prompt — when a predicate can't be translated
# ─────────────────────────────────────────────

PREDICATE_REPAIR_PROMPT = """\
The Z3 verifier could not translate this predicate to first-order logic.

## Original predicate
```
{original_expression}
```

## Translation error
{error}

## DSL you must use
{dsl}

## Context (the code the predicate was extracted from)
```
{code}
```

## Task
Reformulate the predicate so it conforms to the DSL above. If it
fundamentally cannot fit (e.g. it talks about temporal behavior or
information flow), return logic_type other than 'fol'.

Return ONLY this JSON object:
{{
  "expression": "<reformulated predicate>",
  "logic_type": "<fol|temporal|info_flow|behavioral|probabilistic|semantic>",
  "natural_language": "<unchanged or refined explanation>"
}}\
"""


# ─────────────────────────────────────────────
#  Grounding block — injected by the extractor when KB has matches
# ─────────────────────────────────────────────

GROUNDING_BLOCK_TEMPLATE = """\

## Verified Taint Context
The following taint sources and sinks were identified by the static
knowledge base in this code. Focus your beliefs on the data flow
between these points — they are the highest-value targets.

Sources (untrusted inputs):
{sources}

Sinks (dangerous functions):
{sinks}

Pre-existing pattern matches (semgrep/bandit-style):
{pattern_matches}\
"""


# ─────────────────────────────────────────────
#  Phase 2: Detect conflicts between two sets of beliefs
# ─────────────────────────────────────────────

DETECT_CONFLICTS_PROMPT = """\
You are given two sets of beliefs from components that interact at a frontier.

## Caller Beliefs (Component A)
```json
{caller_beliefs}
```

## Callee Beliefs (Component B)
```json
{callee_beliefs}
```

## Frontier Context
- Caller: {caller_name}
- Callee: {callee_name}
- Interaction type: {interaction_type}

## Task
Identify conflicts where:
1. A's postcondition contradicts B's precondition
2. A sends data that violates B's assumptions
3. B assumes trust that A does not guarantee
4. A and B have incompatible beliefs about shared state

Return a JSON array of conflict objects:
{{
  "belief_a_id": "<id from caller beliefs>",
  "belief_b_id": "<id from callee beliefs>",
  "conflict_type": "<contradictory|gap|asymmetric_trust|semantic>",
  "severity": "<critical|high|medium|low|info>",
  "description": "<one paragraph explaining the conflict>",
  "exploitation_hypothesis": "<how an attacker could exploit this>",
  "confidence": <0.0 to 1.0>
}}

Output ONLY the JSON array.\
"""

# ─────────────────────────────────────────────
#  Phase 3: Generate exploitation scenario
# ─────────────────────────────────────────────

GENERATE_EXPLOIT_PROMPT = """\
A belief conflict has been detected and formally verified.

## Conflict
{conflict_description}

## Belief A (holds this true)
Predicate: {predicate_a}
Scope: {scope_a}
Justification: {justification_a}

## Belief B (contradicts A)
Predicate: {predicate_b}
Scope: {scope_b}
Justification: {justification_b}

## Source Code Context
```
{code_context}
```

## Task
Generate a concrete exploitation scenario:

{{
  "attack_vector": "<how the attacker reaches the conflict point>",
  "preconditions": ["<state requirements for the attack>"],
  "input_description": "<what the attacker sends>",
  "execution_path": ["<step-by-step execution leading to the vulnerability>"],
  "consequence": "<what happens: crash, info leak, code execution, etc.>",
  "cvss_estimate": "<CRITICAL|HIGH|MEDIUM|LOW>",
  "proof_of_concept": "<minimal Python code to trigger the issue>",
  "remediation": "<how to fix the conflict>"
}}

Output ONLY the JSON object.\
"""

# ─────────────────────────────────────────────
#  Phase 4: Synthesize missing specifications
# ─────────────────────────────────────────────

SYNTHESIZE_SPEC_PROMPT = """\
The following beliefs have weak or no justification (C4, C5, or C6).
Generate code that would add an explicit runtime guard (upgrade to C3).

## Unjustified Beliefs
```json
{beliefs}
```

## Source Code
```
{code}
```

## Task
For each belief, generate:
{{
  "belief_id": "<id>",
  "assertion_code": "<Python assert statement or type annotation>",
  "test_code": "<pytest test function that verifies this belief>",
  "insertion_point": {{
    "file": "<file path>",
    "line": <line number>,
    "position": "before|after"
  }},
  "explanation": "<why this assertion makes the belief explicit>"
}}

Output ONLY the JSON array.\
"""

# ─────────────────────────────────────────────
#  Adversarial: model attacker beliefs
# ─────────────────────────────────────────────

ADVERSARIAL_BELIEFS_PROMPT = """\
You are a world-class offensive security researcher.

Given the following code and its extracted beliefs, identify which beliefs
an attacker would target first and why.

## Code
```
{code}
```

## Extracted Beliefs
```json
{beliefs}
```

## Task
For each targetable belief, provide:
{{
  "target_belief_id": "<id>",
  "attacker_rationale": "<why this belief is attractive to attack>",
  "visibility": "<how easily an attacker can identify this weakness>",
  "attack_complexity": "<LOW|MEDIUM|HIGH>",
  "priority_rank": <1 = highest priority>
}}

Output ONLY the JSON array, ordered by priority_rank ascending.\
"""

# ─────────────────────────────────────────────
#  Configuration extraction from non-code artifacts
# ─────────────────────────────────────────────

EXTRACT_CONFIG_BELIEFS_PROMPT = """\
Analyze this configuration/infrastructure file and extract implicit beliefs.

## File
```
{config_content}
```

## File type: {config_type}
## File path: {file_path}

## Task
Extract beliefs about:
- Network exposure (ports, protocols, access controls)
- Secret management (how credentials are handled)
- Resource limits (memory, CPU, storage assumptions)
- Trust boundaries (what is inside/outside the trust perimeter)
- Dependency assumptions (base images, package versions)

Same output format as code beliefs (JSON array of sextuplets).
Set artifact_kind to the appropriate type (configuration, infrastructure, ci_cd).

Output ONLY the JSON array.\
"""


# ─────────────────────────────────────────────
#  HTTP-context belief extraction (NEW in v2 — for black-box)
# ─────────────────────────────────────────────

EXTRACT_HTTP_BELIEFS_PROMPT = """\
You are analyzing observed HTTP behavior of a web server. Extract the
IMPLICIT beliefs the server appears to hold about its inputs and clients.

## Endpoint
{method} {url}

## Observed responses (clustered, N={n_observations})
```
{observations_summary}
```

## Headers commonly returned
{common_headers}

## Cookies set
{cookies}

## Context
{grounding_block}

## Task
Extract beliefs the SERVER holds — not the client. Examples:
- "The server believes path /admin requires authentication"
  (evidence: 403 returned consistently when no token)
- "The server believes the JWT signature is verified"
  (evidence: claims modified → 401)
- "The server believes input is not larger than X bytes"
  (evidence: 413 above some threshold)

Return JSON array of beliefs in the same format as code beliefs, with:
- predicate.expression: a falsifiable assertion (use HTTP DSL: `path == ...`,
  `header.X exists`, `status == N`, `len(body) <= N`, `cookie.X has flag`)
- scope.line_start = 0, line_end = 0 (HTTP has no lines)
- scope.function_name = "{method} {url}"
- logic_type: 'http_logic' for HTTP-specific, 'fol' if it's a numeric/string
  property, 'semantic' otherwise
- justification: C5 if an explicit protocol specification documents it,
  otherwise C6. Repeated observations are not a mechanical proof.

Output ONLY the JSON array.\
"""
