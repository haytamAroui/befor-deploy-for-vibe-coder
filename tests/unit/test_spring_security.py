from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.spring_security import SpringAnyRequestPermitAllControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


IMPORTS = """import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
"""


def _run(tmp_path: Path, source: str):
    path = tmp_path / "src/main/java/example/SecurityConfig.java"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return SpringAnyRequestPermitAllControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_direct_any_request_permit_all_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SecurityConfig {
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/health").permitAll()
            .anyRequest().permitAll()
        );
        return http.build();
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-SPRING-SECURITY-PERMIT-ALL-001"
    assert finding.evidence == {
        "artifact": "spring_security_java_config",
        "request_scope": "any_request",
        "authorization_rule": "permit_all",
        "syntax": "anyRequest_permitAll",
    }


def test_any_request_authenticated_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SecurityConfig {
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/health").permitAll()
            .anyRequest().authenticated()
        );
        return http.build();
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_narrow_request_matcher_permit_all_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SecurityConfig {
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/health").permitAll()
            .anyRequest().authenticated()
        );
        return http.build();
    }
}
""",
    )

    assert result.findings == ()


def test_comment_and_string_lookalikes_are_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SecurityConfig {
    String example = ".anyRequest().permitAll()";
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        // auth.anyRequest().permitAll();
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }
}
""",
    )

    assert result.findings == ()


def test_missing_http_security_import_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        """import org.springframework.security.web.SecurityFilterChain;
class SecurityConfig {
    SecurityFilterChain chain(HttpSecurity http) {
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return null;
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_no_java_source_is_not_applicable(tmp_path: Path):
    (tmp_path / "README.md").write_text("no Java", encoding="utf-8")
    result = SpringAnyRequestPermitAllControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
