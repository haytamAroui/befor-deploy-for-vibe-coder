from pathlib import Path

from before_deploy.controls.base import ControlContext
from before_deploy.controls.spring_jpa_injection import SpringRequestParamNativeQueryInjectionControl
from before_deploy.inventory import collect_inventory
from before_deploy.models import ExecutionStatus


IMPORTS = """import org.springframework.web.bind.annotation.*;
import jakarta.persistence.EntityManager;
"""


def _run(tmp_path: Path, source: str):
    path = tmp_path / "src/main/java/example/SearchController.java"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return SpringRequestParamNativeQueryInjectionControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )


def test_request_param_directly_concatenated_into_native_query_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String name) {
        return entityManager.createNativeQuery("select * from users where name = '" + name + "'")
            .getResultList();
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "SEC-SPRING-JPA-NATIVE-QUERY-001"
    assert finding.evidence["mapping_annotation"] == "GetMapping"
    assert finding.evidence["request_source"] == "RequestParam"
    assert finding.evidence["request_parameter"] == "name"
    assert finding.evidence["sink"] == "createNativeQuery"


def test_path_variable_with_annotation_arguments_is_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping(path = "/users/{id}")
    Object user(
        @PathVariable(name = "id") String id
    ) {
        return entityManager.createNativeQuery("select * from users where id = " + id).getSingleResult();
    }
}
""",
    )

    assert len(result.findings) == 1
    assert result.findings[0].evidence["request_source"] == "PathVariable"
    assert result.findings[0].evidence["request_parameter"] == "id"


def test_parameter_binding_is_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String name) {
        return entityManager.createNativeQuery("select * from users where name = :name")
            .setParameter("name", name)
            .getResultList();
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_one_local_alias_is_explicitly_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String name) {
        String value = name;
        return entityManager.createNativeQuery("select * from users where name = '" + value + "'")
            .getResultList();
    }
}
""",
    )

    assert result.findings == ()


def test_transformed_request_parameter_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String name) {
        return entityManager.createNativeQuery("select * from users where name = '" + name.trim() + "'")
            .getResultList();
    }
}
""",
    )

    assert result.findings == ()


def test_request_body_field_is_out_of_scope(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @PostMapping("/users")
    Object users(@RequestBody SearchRequest request) {
        return entityManager.createNativeQuery("select * from users where name = '" + request.name() + "'")
            .getResultList();
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_jpql_create_query_is_not_part_of_native_query_contract(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String name) {
        return entityManager.createQuery("select u from User u where u.name = '" + name + "'")
            .getResultList();
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.COMPLETED
    assert result.findings == ()


def test_comment_and_string_lookalikes_are_not_reported(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String name) {
        // entityManager.createNativeQuery("select * from users where name = '" + name + "'");
        String example = "createNativeQuery(\\\"x\\\" + name)";
        return entityManager.createNativeQuery("select 1").getSingleResult();
    }
}
""",
    )

    assert result.findings == ()


def test_unrelated_string_parameter_is_not_used_as_source(tmp_path: Path):
    result = _run(
        tmp_path,
        IMPORTS
        + """
class SearchController {
    EntityManager entityManager;

    @GetMapping("/users")
    Object users(@RequestParam String requested, String internalName) {
        return entityManager.createNativeQuery("select * from users where name = '" + internalName + "'")
            .getResultList();
    }
}
""",
    )

    assert result.findings == ()


def test_missing_jpa_import_is_not_applicable(tmp_path: Path):
    result = _run(
        tmp_path,
        """import org.springframework.web.bind.annotation.*;
class SearchController {
    @GetMapping("/users")
    Object users(@RequestParam String name) {
        return entityManager.createNativeQuery("select * from users where name = '" + name + "'");
    }
}
""",
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()


def test_no_java_source_is_not_applicable(tmp_path: Path):
    (tmp_path / "README.md").write_text("no Java", encoding="utf-8")
    result = SpringRequestParamNativeQueryInjectionControl().run(
        ControlContext(repository_root=tmp_path, inventory=collect_inventory(tmp_path))
    )

    assert result.execution.status == ExecutionStatus.NOT_APPLICABLE
    assert result.findings == ()
