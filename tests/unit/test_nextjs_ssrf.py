from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.nextjs_ssrf import NextDirectQueryFetchSsrfControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, source: str, *, nextjs: bool = True, filename: str = "app/api/proxy/route.ts"):
    if nextjs:
        (tmp_path / "package.json").write_text(
            '{"dependencies":{"next":"16.0.0"}}', encoding="utf-8"
        )
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return NextDirectQueryFetchSsrfControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_nexturl_search_param_to_fetch_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''import { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
  return fetch(request.nextUrl.searchParams.get("url"));
}
''',
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-NEXT-SSRF-001"
    assert finding.location is not None
    assert finding.location.start_line == 4
    assert finding.evidence == {
        "artifact": "nextjs_route_handler",
        "flow": "request_nexturl_searchparam_direct_to_fetch",
        "handler_method": "GET",
    }


def test_post_handler_direct_query_value_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function POST(req: Request) {
  return await fetch(req.nextUrl.searchParams.get("target"));
}
''',
    )
    assert {finding.rule_id for finding in result.findings} == {"SEC-NEXT-SSRF-001"}


def test_one_local_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  const target = request.nextUrl.searchParams.get("url");
  return fetch(target);
}
''',
    )
    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_new_url_request_url_form_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  return fetch(new URL(request.url).searchParams.get("url"));
}
''',
    )
    assert result.findings == ()


def test_literal_fetch_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  return fetch("https://example.com/health");
}
''',
    )
    assert result.findings == ()


def test_comment_and_string_lookalikes_are_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  // fetch(request.nextUrl.searchParams.get("url"));
  const example = "fetch(request.nextUrl.searchParams.get('url'))";
  return new Response(example);
}
''',
    )
    assert result.findings == ()


def test_non_route_source_file_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  return fetch(request.nextUrl.searchParams.get("url"));
}
''',
        filename="app/lib/proxy.ts",
    )
    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_non_nextjs_repository_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  return fetch(request.nextUrl.searchParams.get("url"));
}
''',
        nextjs=False,
    )
    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
