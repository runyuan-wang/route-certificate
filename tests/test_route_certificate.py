from __future__ import annotations

import builtins
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

import route_certificate as routecert  # noqa: E402
from integrations.lingtai.return_observer_adapter import (  # noqa: E402
    NOTICE_SCHEMA,
    TESTED_LINGTAI_COMMIT,
    publish_with_optional_observation,
)
from integrations.lingtai.shadow_adapter import map_shadow_inputs  # noqa: E402

EXAMPLES = ROOT / "examples"
NOW = "2026-08-13T12:00:00Z"


def load(relative: str):
    return routecert.load_json_strict((EXAMPLES / relative).read_bytes())


def fixture():
    cert = load("certificate.json")
    task = load("task.json")
    sources = load("sources.json")
    rubric = load("rubric.json")
    producer = load("receipts/producer-receipt-001.json")
    return cert, task, sources, rubric, producer


def validate(*, cert=None, task=None, sources=None, rubric=None, producer=None, root=EXAMPLES, now=NOW):
    base_cert, base_task, base_sources, base_rubric, base_producer = fixture()
    return routecert.validate_certificate(
        base_cert if cert is None else cert,
        task=base_task if task is None else task,
        sources=base_sources if sources is None else sources,
        rubric=base_rubric if rubric is None else rubric,
        producer_receipt=base_producer if producer is None else producer,
        artifact_root=root,
        now=now,
    )


def codes(receipt):
    return {
        item.split(":", 1)[0]
        for check in receipt["checks"].values()
        for item in check["errors"]
    }


class CoreTests(unittest.TestCase):
    def test_baseline_current_validation_passes_but_semantic_is_not_performed(self):
        receipt = validate()
        self.assertEqual(receipt["overall"], "pass")
        self.assertEqual(receipt["checks"]["semantic"]["status"], "not_performed")
        self.assertIn("not semantic truth", receipt["semantic_limit"])
        self.assertRegex(receipt["digest"], r"^sha256:[0-9a-f]{64}$")

    def test_canonical_round_trip_and_digest_are_deterministic(self):
        cert, *_ = fixture()
        first = routecert.canonical_bytes(cert)
        second = routecert.canonical_bytes(routecert.load_json_strict(first))
        self.assertEqual(first, second)
        self.assertEqual(routecert.canonical_digest(cert), routecert.canonical_digest(routecert.load_json_strict(first)))

    def test_strict_json_profile_rejects_duplicate_float_nonfinite_and_bad_numbers(self):
        for text in ['{"a":1,"a":2}', '{"a":1.25}', '{"a":NaN}', '{"a":Infinity}', '{"a":01}']:
            with self.subTest(text=text), self.assertRaises(routecert.RouteCertError):
                routecert.load_json_strict(text)
        for value in ({"a": 2**60}, {"a": 1.0}, {"a": "\ud800"}, {"a": "e\u0301"}, {"a": "line\nbreak"}):
            with self.subTest(value=repr(value)), self.assertRaises(routecert.RouteCertError):
                routecert.canonical_bytes(value)

    def test_strict_profile_rejects_secret_private_path_and_forbidden_authority_fields(self):
        cases = [
            {"value": "Bearer abcdefghijklmnop"},
            {"value": "api_key=not-a-real-secret"},
            {"value": "/home/example/private/data.json"},
            {"value": "C:\\private\\data.json"},
            {"final_verdict": "pass"},
            {"approval_score": 1},
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(routecert.RouteCertError):
                routecert.canonical_bytes(value)

    def test_id_helper_and_json_pointer_escape(self):
        self.assertTrue(routecert.is_valid_id("source:example-1"))
        self.assertFalse(routecert.is_valid_id(" bad"))
        obj = {"a.b[0]": {"slash/key": {"tilde~key": "é"}}}
        self.assertEqual(routecert.core.get_pointer(obj, "/a.b[0]/slash~1key/tilde~0key"), "é")
        self.assertIn("/a.b[0]/slash~1key/tilde~0key", routecert.core.iter_leaf_pointers(obj))
        with self.assertRaises(routecert.RouteCertError):
            routecert.core.get_pointer({"~2": "value"}, "/~2")

    def test_task_source_and_rubric_identity_version_digest_bindings(self):
        cert, task, sources, rubric, _ = fixture()
        task["objective"] = "changed"
        self.assertIn("TASK_DIGEST_MISMATCH", codes(validate(task=task)))
        cert, task, sources, rubric, _ = fixture()
        sources["source-primary-001"]["title"] = "changed"
        self.assertIn("SOURCE_DIGEST_MISMATCH", codes(validate(sources=sources)))
        cert, task, sources, rubric, _ = fixture()
        rubric["criteria"].append("changed")
        self.assertIn("RUBRIC_DIGEST_MISMATCH", codes(validate(rubric=rubric)))
        cert, *_ = fixture()
        cert["task_binding"]["version"] = "v2"
        self.assertIn("TASK_VERSION_MISMATCH", codes(validate(cert=cert)))

    def test_source_binding_cardinality_duplicates_missing_and_extra(self):
        cert, _, sources, _, _ = fixture()
        cert["source_bindings"] = []
        self.assertIn("EMPTY_SOURCE_BINDINGS", codes(validate(cert=cert)))
        cert, *_ = fixture()
        cert["source_bindings"].append(copy.deepcopy(cert["source_bindings"][0]))
        self.assertIn("DUPLICATE_SOURCE_BINDING", codes(validate(cert=cert)))
        self.assertIn("SOURCE_UNRESOLVED", codes(validate(sources={})))
        extra = copy.deepcopy(sources)
        extra["source-extra"] = {"id": "source-extra", "version": "v1"}
        self.assertIn("UNBOUND_EXTRA_SOURCE", codes(validate(sources=extra)))

    def test_timestamps_reject_future_expiry_stale_order_and_loose_format(self):
        cert, *_ = fixture()
        cert["created_at"] = "2026-08-14T00:00:00Z"
        cert["expires_at"] = "2026-08-20T00:00:00Z"
        self.assertIn("FUTURE_CERTIFICATE", codes(validate(cert=cert)))
        self.assertIn("STALE_CERTIFICATE", codes(validate(now="2026-08-20T00:00:00Z")))
        cert, *_ = fixture()
        cert["expires_at"] = cert["created_at"]
        self.assertIn("BAD_TIME_ORDER", codes(validate(cert=cert)))
        cert, *_ = fixture()
        cert["created_at"] = "2026-08-13 00:00:00Z"
        self.assertIn("BAD_TIME", codes(validate(cert=cert)))

    def test_uncertainty_conditions_and_lineage_trigger_fail_closed(self):
        for group, fields in (
            ("uncertainty", ("unknown", "not_checked", "uncontrolled")),
            ("conditions", ("no_go", "conflicts", "staleness", "reopen")),
        ):
            for field in fields:
                cert, *_ = fixture()
                cert[group][field] = ["trigger"]
                receipt = validate(cert=cert)
                self.assertEqual(receipt["overall"], "fail")
                self.assertIn(field.upper(), codes(receipt))
        cert, *_ = fixture()
        cert["lineage"]["dependencies"] = [{"from": "a", "to": "b"}, {"from": "b", "to": "a"}]
        got = codes(validate(cert=cert))
        self.assertIn("LINEAGE_DEPENDENCY", got)
        self.assertIn("CYCLIC_LINEAGE", got)

    def test_artifact_path_digest_missing_and_symlink_fail(self):
        cert, *_ = fixture()
        cert["fallback"]["raw_source_refs"][0]["relative_ref"] = "../escape.json"
        self.assertIn("PATH_CONTAINMENT", codes(validate(cert=cert)))
        cert, *_ = fixture()
        cert["fallback"]["raw_source_refs"][0]["artifact_sha256"] = "sha256:" + "0" * 64
        self.assertIn("ARTIFACT_DIGEST_MISMATCH", codes(validate(cert=cert)))
        cert, *_ = fixture()
        cert["fallback"]["raw_source_refs"][0]["relative_ref"] = "sources/missing.json"
        self.assertIn("ARTIFACT_UNAVAILABLE", codes(validate(cert=cert)))

        cert, task, sources, rubric, producer = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sources").mkdir()
            (root / "receipts").mkdir()
            shutil.copy2(EXAMPLES / "receipts/producer-receipt-001.json", root / "receipts/producer-receipt-001.json")
            outside = root / "outside.json"
            outside.write_bytes((EXAMPLES / "sources/source-primary-001.json").read_bytes())
            try:
                (root / "sources/source-primary-001.json").symlink_to(outside)
            except OSError:
                self.skipTest("symlinks unavailable")
            receipt = routecert.validate_certificate(
                cert,
                task=task,
                sources=sources,
                rubric=rubric,
                producer_receipt=producer,
                artifact_root=root,
                now=NOW,
            )
            self.assertIn("ARTIFACT_UNAVAILABLE", codes(receipt))

    def test_producer_receipt_object_and_exact_artifact_are_both_bound(self):
        cert, task, sources, rubric, producer = fixture()
        changed = copy.deepcopy(producer)
        changed["producer_claim"] = "changed"
        self.assertIn("PRODUCER_RECEIPT_DIGEST_MISMATCH", codes(validate(producer=changed)))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sources").mkdir()
            (root / "receipts").mkdir()
            shutil.copy2(EXAMPLES / "sources/source-primary-001.json", root / "sources/source-primary-001.json")
            unrelated = b'{"schema_version":"different.receipt","receipt_id":"other"}\n'
            (root / "receipts/producer-receipt-001.json").write_bytes(unrelated)
            cert["producer_receipt_ref"]["artifact_sha256"] = "sha256:" + hashlib.sha256(unrelated).hexdigest()
            receipt = routecert.validate_certificate(
                cert,
                task=task,
                sources=sources,
                rubric=rubric,
                producer_receipt=producer,
                artifact_root=root,
                now=NOW,
            )
            self.assertIn("PRODUCER_RECEIPT_ARTIFACT_MISMATCH", codes(receipt))

    def test_named_projection_has_mandatory_visible_fields_and_exact_coverage(self):
        cert, *_ = fixture()
        projection = routecert.build_profile_projection(cert)
        self.assertEqual(projection["projection_profile"], routecert.CONSUMER_PROJECTION_PROFILE)
        paths = {item["path"] for item in projection["included"]}
        for path in (
            "/task_binding/id",
            "/source_bindings/0/digest",
            "/route/risk_order/0",
            "/route/heading_evidence_inventory/2/heading",
            "/fallback/raw_source_refs/0/artifact_sha256",
            "/validation_state/semantic",
        ):
            self.assertIn(path, paths)
        all_paths = set(routecert.core.iter_leaf_pointers(cert))
        projected = paths | {item["path"] for item in projection["deferred"]}
        self.assertEqual(projected, all_paths)
        self.assertEqual(routecert.verify_projection_equivalence(cert, projection)["status"], "pass")

    def test_unsafe_selected_projection_and_tampering_fail_equivalence(self):
        cert, *_ = fixture()
        unsafe = routecert.build_projection(cert, ["/certificate_id", "/authority/mode"])
        self.assertEqual(routecert.verify_projection_equivalence(cert, unsafe)["status"], "fail")
        projection = routecert.build_profile_projection(cert)
        variants = []
        tampered = copy.deepcopy(projection)
        tampered["included"][0]["value"] = "tampered"
        variants.append(tampered)
        tampered = copy.deepcopy(projection)
        tampered["deferred"].append(copy.deepcopy(tampered["deferred"][0]))
        variants.append(tampered)
        tampered = copy.deepcopy(projection)
        tampered["ordered_heading_evidence_inventory"].reverse()
        variants.append(tampered)
        tampered = copy.deepcopy(projection)
        tampered["extra"] = True
        variants.append(tampered)
        for value in variants:
            with self.subTest(errors=routecert.verify_projection_equivalence(cert, value)["errors"]):
                self.assertEqual(routecert.verify_projection_equivalence(cert, value)["status"], "fail")

    def test_raw_fallback_transitions(self):
        cert, _, sources, _, _ = fixture()
        self.assertEqual(routecert.resolve_fallback(cert, sources, artifact_root=EXAMPLES)["transition"], "not_loaded")
        self.assertEqual(routecert.resolve_fallback(cert, sources, artifact_root=EXAMPLES, prior_loaded=True)["transition"], "already_loaded")
        cert["conditions"]["reopen"] = ["trigger"]
        self.assertEqual(routecert.resolve_fallback(cert, sources, artifact_root=EXAMPLES)["transition"], "load_full_material")
        cert["fallback"]["raw_source_refs"][0]["artifact_sha256"] = "sha256:" + "0" * 64
        self.assertEqual(routecert.resolve_fallback(cert, sources, artifact_root=EXAMPLES)["transition"], "fail_closed_unavailable")

    def test_decision_envelope_accepted_advisory_and_separate_receipts(self):
        cert, task, sources, rubric, producer = fixture()
        projection = routecert.build_profile_projection(cert)
        envelope = routecert.build_decision_envelope(
            cert,
            projection,
            producer,
            task=task,
            sources=sources,
            rubric=rubric,
            artifact_root=EXAMPLES,
            now=NOW,
        )
        self.assertEqual(envelope["consumer_disposition"], "accepted_advisory")
        self.assertNotEqual(envelope["producer_receipt_ref"]["digest"], envelope["consumer_validation_receipt_ref"]["digest"])
        self.assertTrue(envelope["no_final_judgment"])
        self.assertTrue(envelope["baseline_execution_required"])
        self.assertFalse(envelope["effects_applied"])

    def test_envelope_reopens_material_failure_and_empties_invalid_projection(self):
        cert, task, sources, rubric, producer = fixture()
        projection = routecert.build_profile_projection(cert)
        projection["included"][0]["value"] = "tampered"
        envelope = routecert.build_decision_envelope(
            cert,
            projection,
            producer,
            task=task,
            sources=sources,
            rubric=rubric,
            artifact_root=EXAMPLES,
            now=NOW,
        )
        self.assertEqual(envelope["consumer_disposition"], "reopened_full")
        self.assertEqual(envelope["fallback_result"]["transition"], "load_full_material")
        self.assertEqual(envelope["included"], [])
        self.assertEqual(envelope["deferred"], [])

    def test_envelope_policy_refusal_is_rejected_without_pretend_raw_load(self):
        cert, task, sources, rubric, producer = fixture()
        projection = routecert.build_profile_projection(cert)
        for attempts in ([], 0, "false", {"source_available": False}, {"baseline_execution_required": False}, {"authority": "gate"}):
            envelope = routecert.build_decision_envelope(
                cert,
                projection,
                producer,
                task=task,
                sources=sources,
                rubric=rubric,
                artifact_root=EXAMPLES,
                consumer_attempts=attempts,
                now=NOW,
            )
            self.assertEqual(envelope["consumer_disposition"], "rejected")
            self.assertEqual(envelope["fallback_result"]["transition"], "not_loaded")
            self.assertFalse(envelope["effects_applied"])

    def test_unavailable_raw_material_fails_closed(self):
        cert, task, sources, rubric, producer = fixture()
        projection = routecert.build_profile_projection(cert)
        envelope = routecert.build_decision_envelope(
            cert,
            projection,
            producer,
            task=task,
            sources=sources,
            rubric=rubric,
            artifact_root=ROOT / "not-present",
            now=NOW,
        )
        self.assertEqual(envelope["consumer_disposition"], "failed_closed")
        self.assertFalse(envelope["source_availability"]["raw_source_available"])

    def test_public_entry_points_fail_closed_for_malformed_and_cyclic_values(self):
        cert, task, sources, rubric, producer = fixture()
        cyclic = {}
        cyclic["self"] = cyclic
        receipt = routecert.validate_certificate(
            cyclic,
            task=task,
            sources=sources,
            rubric=rubric,
            producer_receipt=producer,
            artifact_root=EXAMPLES,
            now=NOW,
        )
        self.assertEqual(receipt["overall"], "fail")
        with self.assertRaises(routecert.RouteCertError):
            routecert.build_profile_projection(cyclic)
        self.assertEqual(routecert.verify_projection_equivalence(cyclic, {})["status"], "fail")
        envelope = routecert.build_decision_envelope(
            "bad",
            {},
            producer,
            task=task,
            sources=sources,
            rubric=rubric,
            artifact_root=EXAMPLES,
            now=NOW,
        )
        self.assertEqual(envelope["consumer_disposition"], "failed_closed")

    def test_schemas_are_closed_draft_2020_12_and_match_runtime(self):
        schema_dir = ROOT / "src/route_certificate/schemas"
        names = {
            "certificate.v0.schema.json",
            "decision-envelope.v0.schema.json",
            "projection.v0.schema.json",
            "consumer-validation-receipt.v0.schema.json",
        }
        self.assertEqual({path.name for path in schema_dir.glob("*.json")}, names)
        for name in names:
            schema = routecert.load_json_strict((schema_dir / name).read_bytes())
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            self.assertIn("https://raw.githubusercontent.com/runyuan-wang/route-certificate/main/", schema["$id"])
        certificate_schema = routecert.load_json_strict((schema_dir / "certificate.v0.schema.json").read_bytes())
        self.assertEqual(set(certificate_schema["required"]), routecert.core.MANDATORY_CERT_KEYS)

    def test_generic_core_has_no_lingtai_import(self):
        source = (ROOT / "src/route_certificate/core.py").read_text(encoding="utf-8")
        self.assertNotIn("import lingtai", source.lower())
        original_import = builtins.__import__

        def blocked(name, *args, **kwargs):
            if name.startswith("lingtai"):
                raise AssertionError("generic core attempted LingTai import")
            return original_import(name, *args, **kwargs)

        builtins.__import__ = blocked
        try:
            self.assertEqual(routecert.canonical_digest({"a": 1}), routecert.canonical_digest({"a": 1}))
        finally:
            builtins.__import__ = original_import


class AdapterTests(unittest.TestCase):
    def test_shadow_adapter_maps_good_inputs_without_applying_effects(self):
        _, task, sources, _, _ = fixture()
        output = map_shadow_inputs(
            host_task_id="shadow-task-001",
            task_contract=task,
            sources=sources,
            telemetry={"input_bytes": 1, "output_bytes": 0, "tool_count": 0},
        )
        self.assertEqual(output["status"], "pass")
        self.assertEqual(output["authority_preserved"], "advisory_only")
        self.assertTrue(output["baseline_execution_required"])
        self.assertFalse(output["effects_applied"])

    def test_shadow_adapter_refuses_malformed_secret_path_unknown_and_bool_telemetry_safely(self):
        _, task, sources, _, _ = fixture()
        cases = [
            {"host_task_id": "/home/private/task", "telemetry": {}},
            {"host_task_id": "shadow-task-001", "telemetry": {"api_key": "not-real"}},
            {"host_task_id": "shadow-task-001", "telemetry": {"local_run_label": "../escape"}},
            {"host_task_id": "shadow-task-001", "telemetry": {"input_bytes": True}},
        ]
        for case in cases:
            output = map_shadow_inputs(
                host_task_id=case["host_task_id"],
                task_contract=task,
                sources=sources,
                telemetry=case["telemetry"],
            )
            rendered = json.dumps(output)
            self.assertEqual(output["status"], "fail_closed")
            self.assertNotIn("/home/private", rendered)
            self.assertNotIn("api_key", rendered)
            self.assertFalse(output["effects_applied"])

    def test_return_observer_disabled_never_calls_and_preserves_raw_notification(self):
        called = False

        def observer():
            nonlocal called
            called = True
            raise AssertionError("must not run")

        raw, notification = publish_with_optional_observation(
            enabled=False,
            raw_result=b"raw result",
            ordinary_notification={"status": "done", "preview": "raw result"},
            observe_bounded=observer,
        )
        self.assertFalse(called)
        self.assertEqual(raw, b"raw result")
        self.assertEqual(notification, {"status": "done", "preview": "raw result"})

    def test_return_observer_success_is_additive_only(self):
        notice = {
            "schema_version": NOTICE_SCHEMA,
            "state": "available",
            "generation": "g0000",
            "receipt_digest": "sha256:" + "a" * 64,
            "authority": "advisory_only",
            "raw_result_unchanged": True,
        }
        original = {"status": "failed", "preview": "physical raw evidence", "sequence": 4}
        raw, notification = publish_with_optional_observation(
            enabled=True,
            raw_result=b"physical raw evidence",
            ordinary_notification=original,
            observe_bounded=lambda: notice,
        )
        self.assertEqual(raw, b"physical raw evidence")
        self.assertEqual({key: notification[key] for key in original}, original)
        self.assertEqual(notification["return_observation"], notice)
        self.assertNotIn("return_observation", original)

    def test_return_observer_exception_and_malformed_notice_fail_open(self):
        class StopObserver(BaseException):
            pass

        def interrupted():
            raise StopObserver()

        malformed = {
            "schema_version": NOTICE_SCHEMA,
            "state": "available",
            "generation": "../escape",
            "receipt_digest": "sha256:" + "a" * 64,
            "authority": "advisory_only",
            "raw_result_unchanged": True,
        }
        for observer in (interrupted, lambda: malformed, lambda: {**malformed, "generation": "g0000", "raw_result_unchanged": False}):
            raw, notification = publish_with_optional_observation(
                enabled=True,
                raw_result=b"raw",
                ordinary_notification={"status": "done"},
                observe_bounded=observer,
            )
            self.assertEqual(raw, b"raw")
            self.assertEqual(notification, {"status": "done"})

    def test_reference_integration_labels_exact_tested_commit(self):
        self.assertEqual(TESTED_LINGTAI_COMMIT, "9bb869c4fd101ae1247db0e6b7839138f06abbe7")


class CliTests(unittest.TestCase):
    def run_cli(self, *args, input_text=None):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "route_certificate", *args],
            cwd=ROOT,
            env=env,
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def material_args(self):
        return [
            "--certificate", "examples/certificate.json",
            "--task", "examples/task.json",
            "--sources", "examples/sources.json",
            "--rubric", "examples/rubric.json",
            "--producer-receipt", "examples/receipts/producer-receipt-001.json",
            "--artifact-root", "examples",
            "--now", NOW,
        ]

    def test_version_digest_and_canonicalize(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "route-certificate 0.1.0")
        result = self.run_cli("digest", "examples/certificate.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout.strip(), r"^sha256:[0-9a-f]{64}$")
        result = self.run_cli("canonicalize", "examples/task.json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(routecert.load_json_strict(result.stdout)["id"], "task-review-001")

    def test_validate_project_verify_and_envelope_workflow(self):
        result = self.run_cli("validate", *self.material_args())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["overall"], "pass")
        with tempfile.TemporaryDirectory() as tmp:
            projection_path = Path(tmp) / "projection.json"
            projected = self.run_cli("project", "--certificate", "examples/certificate.json")
            self.assertEqual(projected.returncode, 0, projected.stdout + projected.stderr)
            projection_path.write_text(projected.stdout, encoding="utf-8")
            verified = self.run_cli(
                "verify-projection",
                "--certificate", "examples/certificate.json",
                "--projection", str(projection_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            envelope = self.run_cli("envelope", *self.material_args(), "--projection", str(projection_path))
            self.assertEqual(envelope.returncode, 0, envelope.stdout + envelope.stderr)
            self.assertEqual(json.loads(envelope.stdout)["consumer_disposition"], "accepted_advisory")

    def test_cli_invalid_input_is_sanitized_and_exit_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            hostile = Path(tmp) / "private-name.json"
            hostile.write_text('{"api_key":"not-real-but-secret-shaped"}', encoding="utf-8")
            result = self.run_cli("digest", str(hostile))
            self.assertEqual(result.returncode, 2)
            output = result.stdout + result.stderr
            self.assertNotIn("api_key", output)
            self.assertNotIn(str(hostile), output)
            self.assertEqual(json.loads(result.stdout)["effects_applied"], False)


if __name__ == "__main__":
    unittest.main()
