"""Deterministic execution layer for native advisory repository tools."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Sequence

from before_deploy.agent_repository import (
    RepositoryIndex,
    RepositoryIndexPolicy,
    canonical_repository_path,
    is_test_path,
    path_has_symlink,
)
from before_deploy.agent_runtime import AgentToolRequest, AgentToolResult
from before_deploy.agent_tools import RepositoryToolPolicy


class BoundedRepositoryTools:
    """Authorize and execute read-only repository observations for an agent run."""

    def __init__(
        self,
        repository: Path,
        *,
        starting_paths: Sequence[str] = (),
        policy: RepositoryToolPolicy | None = None,
        index: RepositoryIndex | None = None,
    ) -> None:
        self.policy = policy or RepositoryToolPolicy()
        self.policy.validate()
        self.index = index or RepositoryIndex.build(
            repository,
            policy=RepositoryIndexPolicy(max_file_bytes=self.policy.max_file_bytes),
        )
        self.root = self.index.root
        self.starting_paths = frozenset(canonical_repository_path(path) for path in starting_paths)
        if self.starting_paths - set(self.index.files):
            raise ValueError("Starting context path is outside the bounded repository index")

    def execute(self, request: AgentToolRequest, *, max_bytes: int) -> AgentToolResult:
        if request.tool_name not in self.policy.allowed_tools:
            return self._result(request, "DENIED", {"error": "tool_not_allowed"}, max_bytes)
        if not isinstance(request.arguments, Mapping):
            return self._result(
                request,
                "ERROR",
                {"error": "arguments_must_be_object"},
                max_bytes,
            )
        try:
            payload = self._dispatch(request.tool_name, request.arguments)
            return self._result(request, "OK", payload, max_bytes)
        except ValueError as error:
            return self._result(request, "DENIED", {"error": str(error)}, max_bytes)

    def _dispatch(self, tool_name: str, args: Mapping[str, Any]) -> Mapping[str, Any]:
        if tool_name == "read_file":
            return self._read_file(args)
        if tool_name == "search_text":
            return self._search_text(args)
        if tool_name == "search_symbol":
            return self._search_symbol(args)
        if tool_name == "find_references":
            return self._find_references(args, calls_only=False, tests_only=False)
        if tool_name == "find_callers":
            return self._find_references(args, calls_only=True, tests_only=False)
        if tool_name == "find_tests":
            return self._find_references(args, calls_only=False, tests_only=True)
        if tool_name == "dependency_neighbors":
            return self._dependency_neighbors(args)
        raise ValueError("unsupported_tool")

    def _read_file(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        path = self._authorize_path(_text(args, "path"))
        item = self.index.files[path]
        start = _positive_int(args.get("start_line", 1), "start_line")
        default_end = min(len(item.lines), start + self.policy.max_read_lines - 1)
        end = _positive_int(args.get("end_line", max(default_end, 1)), "end_line")
        if end < start:
            raise ValueError("end_line_before_start_line")
        if item.lines and start > len(item.lines):
            raise ValueError("start_line_out_of_range")
        end = min(end, start + self.policy.max_read_lines - 1, len(item.lines))
        lines = [
            {"line": number, "text": item.lines[number - 1]}
            for number in range(start, end + 1)
        ]
        return {
            "path": path,
            "line_count": len(item.lines),
            "start_line": start,
            "end_line": end,
            "lines": lines,
        }

    def _search_text(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        query = _text(args, "query", max_chars=300)
        matches = [
            (score, path, line, text)
            for score, path, line, text in self.index.lexical_search(query)
            if self._path_is_authorized(path)
        ]
        limited = matches[: self.policy.max_results]
        return {
            "query": query,
            "matches": [
                {"path": path, "line": line, "text": text, "term_hits": -score}
                for score, path, line, text in limited
            ],
            "truncated": len(matches) > len(limited),
            "semantics": "deterministic_lexical_search",
        }

    def _search_symbol(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        symbol = _symbol(args)
        matches = [
            {"path": path, "line": line, "text": text}
            for path, line, text in self.index.definitions(symbol)
            if self._path_is_authorized(path)
        ]
        return {
            "symbol": symbol,
            "definitions": matches[: self.policy.max_results],
            "truncated": len(matches) > self.policy.max_results,
        }

    def _find_references(
        self,
        args: Mapping[str, Any],
        *,
        calls_only: bool,
        tests_only: bool,
    ) -> Mapping[str, Any]:
        symbol = _symbol(args)
        matches = [
            {"path": path, "line": line, "text": text}
            for path, line, text in self.index.references(
                symbol,
                calls_only=calls_only,
                tests_only=tests_only,
            )
            if self._path_is_authorized(path)
        ]
        key = "call_sites" if calls_only else "test_references" if tests_only else "references"
        return {
            "symbol": symbol,
            key: matches[: self.policy.max_results],
            "truncated": len(matches) > self.policy.max_results,
            "semantics": "lexical_static_reference",
        }

    def _dependency_neighbors(self, args: Mapping[str, Any]) -> Mapping[str, Any]:
        path = self._authorize_path(_text(args, "path"))
        imports, importers = self.index.dependency_neighbors(path)
        visible_importers = [item for item in importers if self._path_is_authorized(item)]
        return {
            "path": path,
            "imports": list(imports),
            "possible_importers": visible_importers[: self.policy.max_results],
            "truncated": len(visible_importers) > self.policy.max_results,
            "semantics": "static_import_lexical_neighbors",
        }

    def _authorize_path(self, raw_path: str) -> str:
        path = canonical_repository_path(raw_path)
        if path not in self.index.files:
            raise ValueError("path_outside_bounded_repository_index")
        if not self._path_is_authorized(path):
            raise ValueError("path_outside_authorized_agent_scope")
        if path_has_symlink(self.root, path):
            raise ValueError("symlink_path_denied")
        return path

    def _path_is_authorized(self, path: str) -> bool:
        return self.policy.allow_scope_expansion or path in self.starting_paths

    @staticmethod
    def _result(
        request: AgentToolRequest,
        status: str,
        payload: Mapping[str, Any],
        max_bytes: int,
    ) -> AgentToolResult:
        content, truncated = _bounded_json(payload, max_bytes)
        return AgentToolResult.from_text(
            call_id=request.call_id,
            tool_name=request.tool_name,
            status=status,
            content=content,
            truncated=truncated,
            message=None if status == "OK" else str(payload.get("error", status)),
        )


def _bounded_json(payload: Mapping[str, Any], max_bytes: int) -> tuple[str, bool]:
    if max_bytes <= 0:
        raise ValueError("tool_result_bound_must_be_positive")
    content = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    encoded = content.encode("utf-8")
    if len(encoded) <= max_bytes:
        return content, False
    metadata = json.dumps(
        {
            "truncated": True,
            "original_sha256": sha256(encoded).hexdigest(),
            "original_size_bytes": len(encoded),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(metadata.encode("utf-8")) > max_bytes:
        raise ValueError("tool_result_bound_too_small")
    return metadata, True


def _text(args: Mapping[str, Any], name: str, *, max_chars: int = 500) -> str:
    value = args.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name}_required")
    value = value.strip()
    if len(value) > max_chars:
        raise ValueError(f"{name}_too_long")
    return value


def _symbol(args: Mapping[str, Any]) -> str:
    value = _text(args, "symbol", max_chars=200)
    if not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.:]*", value):
        raise ValueError("symbol_invalid")
    return value.split(".")[-1].split("::")[-1]


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name}_must_be_positive")
    return value
