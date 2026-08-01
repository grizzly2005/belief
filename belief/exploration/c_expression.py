"""Conservative parser for the C boolean subset used by research objectives."""

from __future__ import annotations

import re

MAX_C_CONSTRAINT_LENGTH = 512

_TOKEN = re.compile(
    r"(?P<space>\s+)"
    r"|(?P<integer>0[xX][0-9A-Fa-f]+|0|[1-9][0-9]*)"
    r"|(?P<identifier>[A-Za-z_][A-Za-z0-9_]*)"
    r"|(?P<operator>\|\||&&|==|!=|<=|>=|[()!<>])"
)
_COMPARISONS = {"==", "!=", "<", "<=", ">", ">="}
_C_KEYWORDS = {
    "_Alignas",
    "_Alignof",
    "_Atomic",
    "_Bool",
    "_Complex",
    "_Generic",
    "_Imaginary",
    "_Noreturn",
    "_Static_assert",
    "_Thread_local",
    "alignas",
    "alignof",
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "const",
    "constexpr",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "false",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "nullptr",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "struct",
    "switch",
    "thread_local",
    "true",
    "typedef",
    "typeof",
    "typeof_unqual",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
}


class CConstraintError(ValueError):
    """Raised when a constraint escapes the supported expression subset."""


def normalize_c_boolean_expression(expression: str) -> str:
    """Validate and canonically space one side-effect-free C expression."""

    if not isinstance(expression, str):
        raise CConstraintError("C constraint must be a string")
    if not expression.strip():
        raise CConstraintError("C constraint must not be empty")
    if len(expression) > MAX_C_CONSTRAINT_LENGTH:
        raise CConstraintError(
            f"C constraint exceeds {MAX_C_CONSTRAINT_LENGTH} characters"
        )
    if not expression.isascii():
        raise CConstraintError("C constraint must contain ASCII characters only")

    tokens: list[str] = []
    offset = 0
    while offset < len(expression):
        match = _TOKEN.match(expression, offset)
        if match is None:
            raise CConstraintError(
                f"unsupported C constraint token at offset {offset}"
            )
        offset = match.end()
        if match.lastgroup != "space":
            tokens.append(match.group())
    if not tokens:
        raise CConstraintError("C constraint must contain an expression")

    parser = _Parser(tokens)
    parser.parse_expression()
    if not parser.finished:
        raise CConstraintError(
            f"unexpected C constraint token: {parser.current!r}"
        )
    return " ".join(tokens)


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self._tokens = tokens
        self._index = 0

    @property
    def current(self) -> str | None:
        if self._index >= len(self._tokens):
            return None
        return self._tokens[self._index]

    @property
    def finished(self) -> bool:
        return self.current is None

    def parse_expression(self) -> None:
        self._parse_or()

    def _parse_or(self) -> None:
        self._parse_and()
        while self.current == "||":
            self._consume("||")
            self._parse_and()

    def _parse_and(self) -> None:
        self._parse_not()
        while self.current == "&&":
            self._consume("&&")
            self._parse_not()

    def _parse_not(self) -> None:
        if self.current == "!":
            self._consume("!")
            self._parse_not()
            return
        self._parse_comparison()

    def _parse_comparison(self) -> None:
        self._parse_atom()
        if self.current in _COMPARISONS:
            operator = self.current
            self._consume(operator)
            self._parse_atom()

    def _parse_atom(self) -> None:
        token = self.current
        if token is None:
            raise CConstraintError("C constraint ended unexpectedly")
        if token == "(":
            self._consume("(")
            self.parse_expression()
            self._consume(")")
            return
        if _is_identifier(token) or _is_integer(token):
            self._index += 1
            return
        raise CConstraintError(f"expected identifier, integer, or '(', got {token!r}")

    def _consume(self, expected: str) -> None:
        if self.current != expected:
            raise CConstraintError(
                f"expected {expected!r}, got {self.current!r}"
            )
        self._index += 1


def _is_identifier(token: str) -> bool:
    return (
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) is not None
        and token not in _C_KEYWORDS
    )


def _is_integer(token: str) -> bool:
    return re.fullmatch(
        r"(?:0[xX][0-9A-Fa-f]+|0|[1-9][0-9]*)",
        token,
    ) is not None


__all__ = [
    "CConstraintError",
    "MAX_C_CONSTRAINT_LENGTH",
    "normalize_c_boolean_expression",
]
