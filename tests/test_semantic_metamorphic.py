"""Metamorphic causality tests for reusable semantic primitives."""

from __future__ import annotations

from pathlib import Path

import pytest

from belief.semantic import analyze_semantic_flow


pytestmark = pytest.mark.security


def _has_contract(
    tmp_path: Path,
    source: str,
    contract_id: str,
) -> bool:
    path = tmp_path / "module.py"
    path.write_text(source, encoding="utf-8")
    result = analyze_semantic_flow(tmp_path)
    return contract_id in {concern.contract_id for concern in result.concerns}


@pytest.mark.parametrize(
    "source",
    [
        """
import zlib
def unpack(payload):
    return zlib.decompress(payload)
""",
        """
import zlib
def unpack(payload, other):
    if len(other) > 1024:
        raise ValueError("large")
    return zlib.decompress(payload)
""",
        """
import zlib
def unpack(payload):
    value = zlib.decompress(payload)
    if len(payload) > 1024:
        raise ValueError("large")
    return value
""",
        """
import zlib
def unpack(payload, strict):
    if strict:
        if len(payload) > 1024:
            raise ValueError("large")
    return zlib.decompress(payload)
""",
    ],
)
def test_resource_bound_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-RESOURCE-BOUND",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
import zlib
def unpack(payload):
    if len(payload) > 1024:
        raise ValueError("large")
    return zlib.decompress(payload)
""",
        """
import zlib
def unpack(payload):
    candidate = payload
    if len(candidate) > 1024:
        raise ValueError("large")
    return zlib.decompress(candidate)
""",
        """
import zlib
def reject_large(value):
    if len(value) > 1024:
        raise ValueError("large")

def unpack(payload):
    reject_large(payload)
    return zlib.decompress(payload)
""",
        """
import zlib
def unpack():
    return zlib.decompress(b"fixed")
""",
        """
import zlib
def unpack(payload, compressed):
    if compressed:
        if len(payload) > 1024:
            raise ValueError("large")
        return zlib.decompress(payload)
    return payload
""",
    ],
)
def test_resource_bound_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-RESOURCE-BOUND",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
class HeaderBag:
    def put(self, key, value):
        self.data[key] = value
""",
        """
class HeaderBag:
    def put(self, key, value, other):
        if "\\n" in other:
            raise ValueError("bad")
        self.data[key] = value
""",
        """
class HeaderBag:
    def put(self, key, value):
        self.data[key] = value
        if "\\r" in value:
            raise ValueError("bad")
""",
        """
def sanitize_header(value):
    return value.replace("\\n", "")

class HeaderBag:
    def put(self, key, value):
        sanitize_header(value)
        self.data[key] = value
""",
    ],
)
def test_header_control_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-HEADER-CONTROL-CHARS",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
class HeaderBag:
    def put(self, key, value):
        if "\\n" in value or "\\r" in value:
            raise ValueError("bad")
        self.data[key] = value
""",
        """
def reject_controls(candidate):
    if "\\n" in candidate or "\\r" in candidate:
        raise ValueError("bad")

class HeaderBag:
    def put(self, key, value):
        reject_controls(value)
        self.data[key] = value
""",
        """
def sanitize_header(candidate):
    return candidate.replace("\\n", "").replace("\\r", "")

class HeaderBag:
    def put(self, key, value):
        value = sanitize_header(value)
        self.data[key] = value
""",
        """
def reject_controls(candidate):
    if "\\n" in candidate or "\\r" in candidate:
        raise ValueError("bad")
    return candidate

class HeaderBag:
    def put(self, key, value):
        self.data[key] = reject_controls(value)
""",
    ],
)
def test_header_control_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-HEADER-CONTROL-CHARS",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def go(target):
    return redirect(target)
""",
        """
def go(target, other):
    if not is_safe(other):
        raise ValueError("external")
    return redirect(target)
""",
        """
def go(target):
    result = redirect(target)
    if not is_safe(target):
        raise ValueError("external")
    return result
""",
        """
def go(target, strict):
    if strict:
        if not is_safe(target):
            raise ValueError("external")
    return redirect(target)
""",
    ],
)
def test_redirect_origin_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-REDIRECT-ORIGIN",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def go(target):
    if not is_safe(target):
        raise ValueError("external")
    return redirect(target)
""",
        """
def go(target):
    parsed = urlparse(target)
    if parsed.netloc and parsed.netloc != "service.test":
        raise ValueError("external")
    return redirect(target)
""",
        """
def go(target):
    if is_safe(target):
        return redirect(target)
    raise ValueError("external")
""",
        """
def go():
    return redirect("/account")
""",
    ],
)
def test_redirect_origin_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-REDIRECT-ORIGIN",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def mutate(context, account_id):
    update_account(account_id)
""",
        """
def mutate(context, account_id, other_id):
    if other_id != context.user_id and not context.is_admin:
        raise PermissionError
    update_account(account_id)
""",
        """
def mutate(context, account_id):
    update_account(account_id)
    if account_id != context.user_id and not context.is_admin:
        raise PermissionError
""",
        """
def mutate(context, account_id, strict):
    if strict:
        if account_id != context.user_id and not context.is_admin:
            raise PermissionError
    update_account(account_id)
""",
    ],
)
def test_authorization_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-RESOURCE-AUTHORIZATION",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def mutate(context, account_id):
    if account_id != context.user_id and not context.is_admin:
        raise PermissionError
    update_account(account_id)
""",
        """
@permission_required("account.write")
def mutate(context, account_id):
    update_account(account_id)
""",
        """
@require_admin
def mutate(context, account_id):
    update_account(account_id)
""",
    ],
)
def test_authorization_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-RESOURCE-AUTHORIZATION",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def expand(node):
    if not node:
        return node
    return expand(node.child)
""",
        """
class Walker:
    def expand(self, node):
        return self.expand(node.child)
""",
        """
def expand(node):
    if node.children:
        return expand(node.children[0])
    return node
""",
    ],
)
def test_recursion_bound_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-RECURSION-BOUND",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def expand(node):
    try:
        return expand(node.child)
    except RecursionError:
        raise ValueError("too deep")
""",
        """
def expand(node, depth=0):
    if depth > 100:
        raise ValueError("too deep")
    return expand(node.child, depth + 1)
""",
        """
def expand(parser, node):
    return parser.expand(node)
""",
        """
class Service:
    def expand(self, node):
        return node

    def setup(self):
        def expand(node):
            return self.expand(node)
        return expand
""",
        """
class Tokens:
    def token_index(self, token, start=0):
        start = (
            start
            if isinstance(start, int)
            else self.token_index(start)
        )
        return start + self.tokens[start:].index(token)
""",
    ],
)
def test_recursion_bound_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-RECURSION-BOUND",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def decode(payload):
    while payload:
        payload = unpack_one_layer(payload)
    return payload
""",
        """
def normalize(text):
    while text:
        text = text.strip()
    return text
""",
        """
def traverse(node):
    while node is not None:
        node = node.parent()
    return node
""",
    ],
)
def test_loop_progress_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-LOOP-PROGRESS",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def consume(payload):
    while payload:
        payload = payload[1:]
    return payload
""",
        """
def count(limit):
    index = 0
    while index < limit:
        index += 1
    return index
""",
        """
def decode(payload):
    while payload:
        previous = len(payload)
        payload = unpack_one_layer(payload)
        if len(payload) >= previous:
            raise ValueError("no progress")
    return payload
""",
        """
def ascend(node):
    while node is not None:
        parent = node.parent
        if parent is node:
            raise ValueError("no progress")
        node = parent
    return node
""",
    ],
)
def test_loop_progress_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-LOOP-PROGRESS",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
import re
def validate(value):
    return re.fullmatch(r"(a+)+$", value)
""",
        """
import re
def validate(value):
    return re.match(r"(.*?)*$", value)
""",
        """
import re
def validate(value):
    return re.search(r".*alpha.*omega.*", value)
""",
        """
import re
def validate(value):
    return re.fullmatch(r"(a|aa)+$", value)
""",
        """
import re
def parse_tag(value):
    return re.fullmatch(
        r"(?:\\s+\\w+|\\s*=\\s*|\\\".*?\\\"|'.*?')*",
        value,
    )
""",
        """
import re
def validate_atom(value):
    return re.fullmatch(r"([a-z|~]+)*", value)
""",
        """
import re
def validate_style(value):
    return re.fullmatch(
        r'''([a-z'"]|'[a-z]+'|"[a-z]+")*''',
        value,
    )
""",
    ],
)
def test_regex_complexity_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-REGEX-COMPLEXITY",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
import re
def validate(value):
    return re.fullmatch(r"^.*$", value)
""",
        """
import re
def validate(value):
    return re.fullmatch(r'^[^"]*$', value)
""",
        """
import re
def validate(value):
    if len(value) > 256:
        raise ValueError("large")
    return re.fullmatch(r"(a+)+$", value)
""",
        """
import re
class Validator:
    pattern = re.compile(r"(a+)+$")

    def __call__(self, value):
        if len(value) > 256:
            raise ValueError("large")
        return self.pattern.fullmatch(value)
""",
        """
import re
def parse_tag(value):
    return re.fullmatch(
        r"(?:\\s+\\w+|\\s*=\\s*|\\\"[^\\\"]*?\\\"|'[^']*?'|\\s*,\\s*)*",
        value,
    )
""",
        """
import re
def validate_style(value):
    return re.fullmatch(
        r'''([a-z]|'[a-z]+'|"[a-z]+")*''',
        value,
    )
""",
    ],
)
def test_regex_complexity_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-REGEX-COMPLEXITY",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
async def decode(request):
    await request.body()
    return await request.json()
""",
        """
async def decode(request, other):
    if other.headers.get("content-type") != "application/json":
        raise ValueError("media type")
    await request.body()
    return await request.json()
""",
        """
async def decode(request):
    await request.body()
    value = await request.json()
    if request.headers.get("content-type") != "application/json":
        raise ValueError("media type")
    return value
""",
        """
async def decode(request, strict):
    if strict:
        if request.headers.get("content-type") != "application/json":
            raise ValueError("media type")
    await request.body()
    return await request.json()
""",
    ],
)
def test_content_type_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-CONTENT-TYPE-GATE",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
async def decode(request):
    if request.headers.get("content-type") != "application/json":
        raise ValueError("media type")
    await request.body()
    return await request.json()
""",
        """
async def decode(request):
    await request.body()
    if request.headers.get("content-type") == "application/json":
        return await request.json()
    raise ValueError("media type")
""",
        """
async def decode(request):
    if request.get_content_maintype() != "application":
        raise ValueError("media type")
    await request.body()
    return await request.json()
""",
        """
async def decode(request):
    await request.body()
    content_type = request.headers.get("content-type")
    subtype = parse_subtype(content_type)
    if subtype == "json":
        return await request.json()
    raise ValueError("media type")
""",
    ],
)
def test_content_type_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-CONTENT-TYPE-GATE",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def forward(request, client):
    headers = dict(request.headers)
    client.send(headers=headers)
""",
        """
def forward(request, client):
    headers = dict(request.headers)
    client.send(headers=headers)
    headers.pop("authorization", None)
""",
        """
def forward(request, client):
    headers = dict(request.headers)
    headers.pop("accept", None)
    client.send(headers=headers)
""",
        """
def forward(request, client, debug):
    headers = dict(request.headers)
    if debug:
        headers.pop("authorization", None)
    client.send(headers=headers)
""",
        """
def forward(request, client, auth_enabled):
    headers = dict(request.headers)
    if not auth_enabled:
        headers.pop("authorization", None)
    client.send(headers=headers)
""",
    ],
)
def test_credential_header_scope_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-CREDENTIAL-HEADER-SCOPE",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def forward(request, client):
    headers = dict(request.headers)
    headers.pop("authorization", None)
    client.send(headers=headers)
""",
        """
def forward(request, client):
    headers = {"accept": request.headers.get("accept")}
    client.send(headers=headers)
""",
        """
def forward(request, client):
    headers = filter_headers(request.headers)
    client.send(headers=headers)
""",
        """
def forward(request, client):
    headers = dict(request.headers)
    if "authorization" in headers:
        headers.pop("authorization", None)
    client.send(headers=headers)
""",
        """
def forward(request, client, spider):
    headers = dict(request.headers)
    if http_auth_enabled(spider):
        headers.pop("authorization", None)
    client.send(headers=headers)
""",
    ],
)
def test_credential_header_scope_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-CREDENTIAL-HEADER-SCOPE",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def forward(url, headers):
    return smuggle_url(url, {"http_headers": headers})
""",
        """
def forward(url, client):
    url, metadata = unsmuggle_url(url, {})
    return client.request(
        url,
        headers=metadata.get("http_headers", {}),
    )
""",
        """
def forward(url, client):
    url, serialized = deserialize_url(url)
    return client.send(
        url,
        headers=serialized["http_headers"],
    )
""",
    ],
)
def test_serialized_header_map_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-HEADER-MAP-SCOPE",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def forward(url, referer):
    return smuggle_url(url, {"referer": referer})
""",
        """
class Client:
    def forward(self, url):
        headers = self.get_param("http_headers").copy()
        return self.request(url, headers=headers)
""",
        """
def forward(url, client, info):
    headers = info.get("http_headers")
    return client.request(url, headers=headers)
""",
    ],
)
def test_serialized_header_map_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-HEADER-MAP-SCOPE",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def attach(headers, scheme, credential):
    headers["proxy-authorization"] = credential
""",
        """
def attach(headers, scheme, credential):
    if scheme != "https":
        return
    headers["proxy-authorization"] = credential
""",
        """
def attach(headers, scheme, credential):
    headers["proxy-authorization"] = credential
    if scheme == "https":
        return
""",
    ],
)
def test_proxy_authorization_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-PROXY-AUTH-CONTEXT",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
def attach(headers, scheme, credential):
    if scheme != "https":
        headers["proxy-authorization"] = credential
""",
        """
def attach(headers, scheme, credential):
    if scheme == "https":
        return
    headers["proxy-authorization"] = credential
""",
        """
def attach(headers, scheme, credential):
    if scheme == "http":
        headers["proxy-authorization"] = credential
""",
    ],
)
def test_proxy_authorization_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-PROXY-AUTH-CONTEXT",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
import sys
def emit(metrics):
    args = list(sys.argv)
    metrics({"argv": args})
""",
        """
import sys
def emit(metrics):
    args = list(sys.argv)
    args[0] = "program"
    metrics({"argv": args})
""",
        """
import sys
def emit(metrics):
    args = list(sys.argv)
    redact(args[1])
    metrics({"argv": args})
""",
    ],
)
def test_argv_redaction_positive_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-ARGV-REDACTION",
    )


@pytest.mark.parametrize(
    "source",
    [
        """
import sys
def emit(metrics):
    args = [redact(value) for value in sys.argv]
    metrics({"argv": args})
""",
        """
import sys
def emit(metrics):
    args = list(sys.argv)
    args[1] = "<redacted>"
    metrics({"argv": args})
""",
        """
import sys
def emit(metrics):
    metrics({"argc": len(sys.argv)})
""",
        """
import sys
def emit(metrics):
    args = redact_argv(sys.argv)
    metrics({"argv": args})
""",
        """
import sys
def emit(metrics):
    args = list(sys.argv)
    for index, value in enumerate(args):
        if value.startswith("--secret="):
            args[index] = "*" * 8
    metrics({"argv": args})
""",
    ],
)
def test_argv_redaction_negative_metamorphs(
    tmp_path: Path,
    source: str,
):
    assert not _has_contract(
        tmp_path,
        source,
        "BELIEF-SEM-ARGV-REDACTION",
    )
