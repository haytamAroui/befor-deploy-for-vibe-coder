from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.nextjs_error_leak import NextRouteStackTraceResponseControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


def _run(tmp_path: Path, source: str, name: str = "route.ts"):
    path = tmp_path / "app/api/example" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return NextRouteStackTraceResponseControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_caught_stack_returned_from_nextresponse_json_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function GET() {
  try {
    throw new Error("boom")
  } catch (error) {
    return NextResponse.json({ stack: error.stack }, { status: 500 })
  }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "SEC-NEXT-ERROR-STACK-001"
    assert result.findings[0].evidence["flow"] == "catch_variable_stack_to_json_response"


def test_caught_stack_returned_from_response_json_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function POST() {
  try {
    return Response.json({ ok: true })
  } catch (err) {
    return Response.json({ debug: err.stack })
  }
}
""",
    )

    assert len(result.findings) == 1


def test_stable_public_error_message_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function GET() {
  try {
    return Response.json({ ok: true })
  } catch (error) {
    console.error(error)
    return Response.json({ error: "internal_error" }, { status: 500 })
  }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_exception_message_only_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function GET() {
  try {
    return Response.json({ ok: true })
  } catch (error) {
    return Response.json({ error: error.message }, { status: 500 })
  }
}
""",
    )

    assert result.findings == ()


def test_alias_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function GET() {
  try {
    return Response.json({ ok: true })
  } catch (error) {
    const debug = error.stack
    return Response.json({ debug })
  }
}
""",
    )

    assert result.findings == ()


def test_comment_and_string_lookalikes_are_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function GET() {
  try {
    return Response.json({ ok: true })
  } catch (error) {
    // return Response.json({ stack: error.stack })
    const example = "Response.json({ stack: error.stack })"
    return Response.json({ error: "internal_error" })
  }
}
""",
    )

    assert result.findings == ()


def test_non_route_file_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        """export async function GET() {
  try {} catch (error) { return Response.json({ stack: error.stack }) }
}
""",
        name="page.tsx",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
