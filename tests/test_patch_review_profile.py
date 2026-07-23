"""Regression tests for the explicit patch-review trust-boundary profile."""

from __future__ import annotations

from textwrap import dedent

import pytest

from belief.security_patterns import SecurityPatternExtractor
from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target


pytestmark = pytest.mark.security


def _path_findings(source: str, profile: str = "patch_review"):
    return [
        belief
        for belief in SecurityPatternExtractor(profile).extract(
            dedent(source),
            "changed.py",
        )
        if belief.cwe == "CWE-22"
    ]


def _access_findings(source: str, profile: str = "patch_review"):
    return [
        belief
        for belief in SecurityPatternExtractor(profile).extract(
            dedent(source),
            "changed.py",
        )
        if belief.cwe == "CWE-863"
    ]


def _cwe_findings(source: str, cwe: str, profile: str = "patch_review"):
    return [
        belief
        for belief in SecurityPatternExtractor(profile).extract(
            dedent(source),
            "changed.py",
        )
        if belief.cwe == cwe
    ]


def test_default_profile_does_not_assume_generic_path_parameter_is_external():
    source = """
        import os

        def read_asset(root, path):
            full_path = os.path.join(root, path)
            return open(full_path).read()
    """

    assert _path_findings(source, "default") == []


def test_patch_review_profile_traces_path_parameter_to_real_file_sink():
    source = """
        import os

        def read_asset(root, path):
            full_path = os.path.join(root, path)
            return open(full_path).read()
    """

    findings = _path_findings(source)

    assert len(findings) == 1
    metadata = findings[0].source_metadata
    assert metadata["analysis_profile"] == "patch_review"
    assert metadata["dataflow"]["source"] == "path"
    assert metadata["dataflow"]["sink"] == "open"


def test_commonpath_rejection_before_sink_protects_same_derived_path():
    source = """
        import os

        def read_asset(root, path):
            full_path = os.path.abspath(os.path.join(root, path))
            common_path = os.path.commonpath([root, full_path])
            if common_path != root:
                raise ValueError("outside root")
            return open(full_path).read()
    """

    assert _path_findings(source) == []


def test_commonprefix_is_not_accepted_as_path_containment():
    source = """
        import os

        def read_asset(root, path):
            full_path = os.path.realpath(os.path.join(root, path))
            if os.path.commonprefix([root, full_path]) != root:
                raise ValueError("outside root")
            return open(full_path).read()
    """

    findings = _path_findings(source)

    assert findings
    assert "commonprefix" in findings[0].predicate.natural_language


def test_basename_output_used_by_sink_is_not_tainted():
    source = """
        import os

        def read_asset(root, filename):
            filename = os.path.basename(filename)
            return open(os.path.join(root, filename)).read()
    """

    assert _path_findings(source) == []


def test_clean_path_rejection_protects_alias_before_sink():
    source = """
        import os

        def read_asset(root, path):
            full_path = os.path.join(root, path)
            if not clean_path(root, full_path):
                return None
            return open(full_path).read()
    """

    assert _path_findings(source) == []


def test_conditional_default_does_not_erase_path_parameter_provenance():
    vulnerable = """
        import os

        def read_asset(root, path):
            if not path:
                path = "index.html"
            full_path = os.path.join(root, path)
            return serve_file(full_path)
    """
    fixed = """
        import os

        def read_asset(root, path):
            if not path:
                path = "index.html"
            full_path = os.path.join(root, path)
            if not os.path.normpath(full_path).startswith(os.path.normpath(root)):
                raise ValueError("outside root")
            return serve_file(full_path)
    """

    assert len(_path_findings(vulnerable)) == 1
    assert _path_findings(fixed) == []


def test_canonicalizer_helper_return_is_not_treated_as_a_path_sink():
    source = """
        import os

        def _realpath(path):
            if os.path.islink(path):
                return os.path.realpath(path)
            return path
    """

    assert _path_findings(source) == []


def test_url_encoded_traversal_validation_requires_canonicalization_first():
    vulnerable = """
        def validate_path_is_safe(path):
            if ".." in path.split("/"):
                raise ValueError("invalid")
    """
    fixed = """
        from urllib.parse import unquote

        def validate_path_is_safe(path):
            path = unquote(path)
            if ".." in path.split("/"):
                raise ValueError("invalid")
    """

    assert len(_path_findings(vulnerable)) == 1
    assert _path_findings(fixed) == []


def test_authorization_wrapper_must_include_forwarded_route_arguments():
    vulnerable = """
        def protected(func):
            def decorated(*args, **kwargs):
                project_id = request.args.get("project_id")
                if check_authorization("read", project_id):
                    return func(*args, **kwargs)
                raise PermissionError
            return decorated
    """
    fixed = """
        def protected(func):
            def decorated(*args, **kwargs):
                project_id = (
                    kwargs.get("project_id")
                    or request.args.get("project_id")
                )
                if check_authorization("read", project_id):
                    return func(*args, **kwargs)
                raise PermissionError
            return decorated
    """

    findings = _access_findings(vulnerable)

    assert len(findings) == 1
    assert findings[0].source_metadata["dataflow"]["source"] == "kwargs"
    assert _access_findings(fixed) == []
    assert _access_findings(vulnerable, "default") == []


def test_route_selected_object_requires_object_level_view_guard():
    vulnerable = """
        class DeviceView(ListView):
            def get_queryset(self):
                return Device.objects.for_user(self.kwargs["user_id"])
    """
    fixed = """
        class DeviceView(ListView):
            def get_queryset(self):
                return Device.objects.for_user(self.kwargs["user_id"])

            def dispatch(self, request, *args, **kwargs):
                if (
                    int(self.kwargs["user_id"]) == request.user.pk
                    or request.user.has_perm("device.change_device")
                ):
                    return super().dispatch(request, *args, **kwargs)
                raise PermissionDenied
    """

    findings = _access_findings(vulnerable)

    assert len(findings) == 1
    assert findings[0].scope.class_name == "DeviceView"
    assert findings[0].scope.function_name == "get_queryset"
    assert _access_findings(fixed) == []


def test_authentication_only_view_guard_does_not_prove_object_authorization():
    source = """
        class DeviceView(ListView):
            def get_queryset(self):
                return Device.objects.for_user(self.kwargs["user_id"])

            def dispatch(self, request, *args, **kwargs):
                if request.user.is_active is True:
                    return super().dispatch(request, *args, **kwargs)
                raise PermissionDenied
    """

    assert len(_access_findings(source)) == 1


def test_sql_builder_fragment_requires_full_match_or_identifier_validation():
    vulnerable = """
        class Query:
            def add_ordering(self, *ordering):
                self.order_by += ordering
    """
    fixed = """
        class Query:
            def add_ordering(self, *ordering):
                for item in ordering:
                    if not ORDER_PATTERN.fullmatch(item):
                        raise ValueError("invalid ordering")
                self.order_by += ordering
    """

    vulnerable_findings = _cwe_findings(vulnerable, "CWE-89")

    assert len(vulnerable_findings) == 1
    assert (
        vulnerable_findings[0].source_metadata["dataflow"]["source"]
        == "ordering"
    )
    assert _cwe_findings(fixed, "CWE-89") == []
    assert _cwe_findings(vulnerable, "CWE-89", "default") == []


def test_savepoint_name_validator_protects_attribute_alias():
    vulnerable = """
        class PostgresSavepoint:
            def __init__(self, name):
                self.name = name
    """
    fixed = """
        class PostgresSavepoint:
            def __init__(self, name):
                self.name = name
                validate_savepoint_name(self.name)
    """

    assert len(_cwe_findings(vulnerable, "CWE-89")) == 1
    assert _cwe_findings(fixed, "CWE-89") == []


def test_validated_savepoint_attribute_suppresses_formatted_execute_signal():
    vulnerable = """
        class PostgresSavepoint:
            async def rollback_to(self):
                await self.connection.execute(
                    f"ROLLBACK TO SAVEPOINT {self.name}"
                )
    """
    fixed = """
        class PostgresSavepoint:
            async def rollback_to(self):
                validate_savepoint_name(self.name)
                await self.connection.execute(
                    f"ROLLBACK TO SAVEPOINT {self.name}"
                )
    """

    assert _cwe_findings(vulnerable, "CWE-89")
    assert _cwe_findings(fixed, "CWE-89") == []


def test_sql_options_consumed_through_named_allowlist_are_validated():
    source = """
        class DatabaseOperations:
            def explain_query_prefix(self, **options):
                extra = {}
                for valid_option in self.explain_options:
                    value = options.pop(valid_option, None)
                    if value is not None:
                        extra[valid_option] = value
                return super().explain_query_prefix(**extra)
    """

    assert _cwe_findings(source, "CWE-89") == []


def test_shell_command_boundary_parameter_requires_abortive_validation():
    vulnerable = """
        import subprocess

        def run_cli(schema):
            command = f"beeline --database {schema}"
            subprocess.Popen(command, shell=True)
    """
    fixed = """
        import subprocess

        def run_cli(schema):
            if "!" in schema or ";" in schema:
                raise ValueError("invalid schema")
            command = f"beeline --database {schema}"
            subprocess.Popen(command, shell=True)
    """

    findings = _cwe_findings(vulnerable, "CWE-78")

    assert len(findings) == 1
    assert findings[0].source_metadata["analysis_profile"] == "patch_review"
    assert _cwe_findings(fixed, "CWE-78") == []


def test_cli_script_fragment_rejects_command_delimiters_before_embedding():
    vulnerable = """
        class HiveCliHook:
            def run_cli(self, hql, schema):
                if schema:
                    hql = f"USE {schema};\\n{hql}"
                return self.execute_cli_file(hql)
    """
    fixed = """
        class HiveCliHook:
            def run_cli(self, hql, schema):
                if "!" in schema or ";" in schema:
                    raise ValueError("invalid schema")
                if schema:
                    hql = f"USE {schema};\\n{hql}"
                return self.execute_cli_file(hql)
    """

    findings = _cwe_findings(vulnerable, "CWE-78")

    assert len(findings) == 1
    assert findings[0].source_metadata["analysis_profile"] == "patch_review"
    assert _cwe_findings(fixed, "CWE-78") == []


def test_patch_profile_traces_boundary_value_into_unsafe_html_marker():
    vulnerable = """
        def label_from_instance(obj):
            bits = [obj.name, obj.description]
            return mark_safe("<br>".join(bits))
    """
    fixed = """
        def label_from_instance(obj):
            bits = [obj.name, obj.description]
            return format_html("{}<br>{}", *bits)
    """

    findings = _cwe_findings(vulnerable, "CWE-79")

    assert findings
    assert any(
        finding.source_metadata.get("analysis_profile") == "patch_review"
        for finding in findings
    )
    assert _cwe_findings(fixed, "CWE-79") == []


def test_collection_built_from_boundary_objects_remains_tainted_at_html_sink():
    source = """
        class PageChoiceField:
            def label_from_instance(self, obj):
                bits = []
                for ancestor in obj.get_ancestors():
                    bits.append(ancestor.display_title())
                return mark_safe("<br>".join(bits))
    """

    findings = _cwe_findings(source, "CWE-79")

    assert any(
        finding.source_metadata.get("analysis_profile") == "patch_review"
        for finding in findings
    )


def test_url_parameters_remain_tainted_through_augmented_url_construction():
    vulnerable = """
        class RelatedWidget:
            def get_context(self, name, value, attrs):
                related_url = reverse("admin:list")
                params = self.url_parameters()
                if params:
                    related_url += "?" + "&".join(
                        "%s=%s" % (key, item) for key, item in params.items()
                    )
                return mark_safe(related_url)
    """
    fixed = """
        class RelatedWidget:
            def get_context(self, name, value, attrs):
                related_url = reverse("admin:list")
                params = self.url_parameters()
                if params:
                    related_url += "?" + urlencode(params)
                return related_url
    """

    assert any(
        finding.source_metadata.get("analysis_profile") == "patch_review"
        for finding in _cwe_findings(vulnerable, "CWE-79")
    )
    assert _cwe_findings(fixed, "CWE-79") == []


def test_http_handler_does_not_reflect_path_after_constant_error_replacement():
    vulnerable = """
        class AssetHandler:
            def get(self, path):
                self.write(f"{path} was not found")
    """
    fixed = """
        class AssetHandler:
            def get(self, path):
                self.write("not found")
    """

    assert len(_cwe_findings(vulnerable, "CWE-79")) == 1
    assert _cwe_findings(fixed, "CWE-79") == []


def test_tls_proxy_context_requires_hostname_verification():
    vulnerable = """
        def _connect_tls_proxy(hostname, ssl_context):
            return ssl_wrap_socket(
                server_hostname=hostname,
                ssl_context=ssl_context,
            )
    """
    fixed = """
        def _connect_tls_proxy(hostname, ssl_context):
            ssl_context.check_hostname = True
            return ssl_wrap_socket(
                server_hostname=hostname,
                ssl_context=ssl_context,
            )
    """

    findings = _cwe_findings(vulnerable, "CWE-295")

    assert len(findings) == 1
    assert findings[0].source_metadata["analysis_profile"] == "patch_review"
    assert _cwe_findings(fixed, "CWE-295") == []


def test_rsa_block_requires_abortive_canonical_length_guard():
    vulnerable = """
        def verify(message, signature, public_key):
            key_length = byte_size(public_key.n)
            encrypted = bytes2int(signature)
            return decrypt_int(encrypted, public_key)
    """
    fixed = """
        def verify(message, signature, public_key):
            key_length = byte_size(public_key.n)
            encrypted = bytes2int(signature)
            if len(signature) != key_length:
                raise VerificationError("invalid signature")
            return decrypt_int(encrypted, public_key)
    """

    findings = _cwe_findings(vulnerable, "CWE-327")

    assert len(findings) == 1
    assert findings[0].source_metadata["analysis_profile"] == "patch_review"
    assert _cwe_findings(fixed, "CWE-327") == []


def test_signer_salt_uses_explicit_keyword_parameter():
    vulnerable = """
        class Verification:
            def __init__(self):
                self._salt = "registration"
                self._signer = Signer(self._salt)
    """
    fixed = """
        class Verification:
            def __init__(self):
                self._salt = "registration"
                self._signer = Signer(salt=self._salt)
    """

    findings = _cwe_findings(vulnerable, "CWE-347")

    assert len(findings) == 1
    assert findings[0].source_metadata["analysis_profile"] == "patch_review"
    assert _cwe_findings(fixed, "CWE-347") == []


def test_explicit_escape_before_html_sink_is_not_patch_boundary_xss():
    source = """
        def render_name(name):
            safe_name = conditional_escape(name)
            return mark_safe(safe_name)
    """

    findings = _cwe_findings(source, "CWE-79")

    assert findings
    assert all(
        finding.source_metadata.get("analysis_profile") != "patch_review"
        for finding in findings
    )


def test_escaped_regex_callback_with_abortive_http_scheme_guard_is_safe():
    source = """
        def render_description(description):
            def build_link(match):
                text = match.group(1)
                url = match.group(2)
                parsed_url = urlparse(url)
                if not (
                    parsed_url.scheme == "http"
                    or parsed_url.scheme == "https"
                ):
                    return escape(match.group(0))
                return Markup(f'<a href="{url}">{text}</a>')

            escaped = escape(description)
            escaped = re2.sub(PATTERN, build_link, escaped)
            return Markup(escaped)
    """

    findings = _cwe_findings(source, "CWE-79")

    assert findings
    assert all(
        finding.source_metadata.get("analysis_profile") != "patch_review"
        for finding in findings
    )


def test_escaped_regex_callback_without_url_scheme_guard_remains_unsafe():
    source = """
        def render_description(description):
            def build_link(match):
                text = match.group(1)
                url = match.group(2)
                return Markup(f'<a href="{url}">{text}</a>')

            escaped = escape(description)
            escaped = re2.sub(PATTERN, build_link, escaped)
            return Markup(escaped)
    """

    findings = _cwe_findings(source, "CWE-79")

    assert any(
        finding.source_metadata.get("analysis_profile") == "patch_review"
        for finding in findings
    )


def test_unsafe_scheme_allowlist_does_not_suppress_callback_finding():
    source = """
        def render_description(description):
            def build_link(match):
                text = match.group(1)
                url = match.group(2)
                parsed_url = urlparse(url)
                if parsed_url.scheme not in {"https", "javascript"}:
                    return escape(match.group(0))
                return Markup(f'<a href="{url}">{text}</a>')

            escaped = escape(description)
            escaped = re2.sub(PATTERN, build_link, escaped)
            return Markup(escaped)
    """

    findings = _cwe_findings(source, "CWE-79")

    assert any(
        finding.source_metadata.get("analysis_profile") == "patch_review"
        for finding in findings
    )


def test_url_scheme_guard_does_not_sanitize_unescaped_callback_text():
    source = """
        def render_description(description):
            def build_link(match):
                text = match.group(1)
                url = match.group(2)
                parsed_url = urlparse(url)
                if parsed_url.scheme not in {"http", "https"}:
                    return match.group(0)
                return Markup(f'<a href="{url}">{text}</a>')

            return re2.sub(PATTERN, build_link, description)
    """

    findings = _cwe_findings(source, "CWE-79")

    assert any(
        finding.source_metadata.get("analysis_profile") == "patch_review"
        for finding in findings
    )


def test_pipeline_exposes_patch_review_profile_without_changing_default(tmp_path):
    target = tmp_path / "changed.py"
    target.write_text(
        dedent(
            """
            import os

            def read_asset(root, key):
                full_path = os.path.join(root, key)
                return open(full_path).read()
            """
        ),
        encoding="utf-8",
    )

    default_result = analyze_static_target(
        target,
        StaticAnalysisOptions(selected_categories=frozenset({"security"})),
    )
    patch_result = analyze_static_target(
        target,
        StaticAnalysisOptions(
            selected_categories=frozenset({"security"}),
            security_analysis_profile="patch_review",
        ),
    )

    assert not any(finding.cwe == "CWE-22" for finding in default_result.findings)
    assert any(finding.cwe == "CWE-22" for finding in patch_result.findings)


def test_pipeline_rejects_unknown_security_profile(tmp_path):
    target = tmp_path / "changed.py"
    target.write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="security_analysis_profile"):
        analyze_static_target(
            target,
            StaticAnalysisOptions(security_analysis_profile="fixture_magic"),
        )
