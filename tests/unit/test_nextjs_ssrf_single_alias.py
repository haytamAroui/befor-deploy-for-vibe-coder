from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.nextjs_ssrf_single_alias import NextSingleAliasQueryFetchSsrfControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, source: str, *, filename: str = "app/api/proxy/route.ts"):
    package = tmp_path / "package.json"
    package.write_text('{"dependencies":{"next":"16.0.0"}}', encoding="utf-8")
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return NextSingleAliasQueryFetchSsrfControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_one_local_alias_query_value_to_fetch_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url")
  return fetch(target)
}
''',
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-NEXT-SSRF-ALIAS-001"
    assert finding.evidence == {
        "artifact": "nextjs_route_handler",
        "flow": "request_nexturl_searchparam_single_alias_to_fetch",
        "handler_method": "GET",
    }


def test_post_handler_and_fetch_options_are_supported(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function POST(req: Request) {
  let destination = req.nextUrl.searchParams.get("target");
  return fetch(destination, { cache: "no-store" })
}
''',
    )

    assert {finding.rule_id for finding in result.findings} == {"SEC-NEXT-SSRF-ALIAS-001"}


def test_direct_flow_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  return fetch(request.nextUrl.searchParams.get("url"))
}
''',
    )

    assert result.findings == ()


def test_chained_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url")
  const destination = target
  return fetch(destination)
}
''',
    )

    assert result.findings == ()


def test_transformed_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url")
  return fetch(target.trim())
}
''',
    )

    assert result.findings == ()


def test_reassigned_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  let target = request.nextUrl.searchParams.get("url")
  target = "https://example.test"
  return fetch(target)
}
''',
    )

    assert result.findings == ()


def test_branch_between_assignment_and_sink_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url")
  if (!target) return new Response("missing")
  return fetch(target)
}
''',
    )

    assert result.findings == ()


def test_new_url_request_url_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: Request) {
  const url = new URL(request.url)
  const target = url.searchParams.get("target")
  return fetch(target)
}
''',
    )

    assert result.findings == ()


def test_non_route_file_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        '''export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url")
  return fetch(target)
}
''',
        filename="lib/proxy.ts",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_non_nextjs_repository_is_not_applicable(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies":{}}', encoding="utf-8")
    path = tmp_path / "app/api/proxy/route.ts"
    path.parent.mkdir(parents=True)
    path.write_text(
        '''export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url")
  return fetch(target)
}
''',
        encoding="utf-8",
    )
    result = NextSingleAliasQueryFetchSsrfControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
