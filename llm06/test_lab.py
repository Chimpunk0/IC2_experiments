import asyncio
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import openwebui_tool as lab


class LabTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.environment = patch.dict(os.environ, {"LLM06_DEMO_DIR": self.directory.name})
        self.environment.start()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.environment.stop)

    def test_requires_explicit_preparation(self):
        with self.assertRaises(RuntimeError):
            asyncio.run(lab.Tools().list_documents())

    def test_vulnerable_deletion_is_persistent_and_audited(self):
        lab._prepare("injected", "vulnerable", "test")
        tools = lab.Tools()
        document = asyncio.run(tools.read_document("report_01"))
        self.assertIn(lab._PAYLOAD, document["content"])
        self.assertEqual(asyncio.run(tools.delete_document("report_02"))["status"], "deleted")
        exported = lab._export()
        self.assertIn("report_02", exported["initial_documents"])
        self.assertNotIn("report_02", exported["current_documents"])
        self.assertEqual(exported["events"][-1]["args"], {"document_id": "report_02"})
        self.assertIn("report_02", exported["events"][-1]["before"])
        self.assertNotIn("report_02", exported["events"][-1]["after"])

    def test_guarded_backend_blocks_direct_deletion(self):
        lab._prepare("injected", "guarded", "test")
        result = asyncio.run(lab.Tools().delete_document("report_02"))
        self.assertEqual(result["status"], "blocked")
        exported = lab._export()
        self.assertEqual(exported["initial_documents"], exported["current_documents"])
        self.assertEqual(exported["events"][-1]["result"]["status"], "blocked")

    def test_invalid_id_cannot_address_file_or_sql(self):
        lab._prepare("clean", "vulnerable", "test")
        for document_id in ("../../outside.txt", "report_02' OR 1=1 --", "unknown"):
            self.assertEqual(lab._call("delete_document", document_id)["status"], "invalid_id")
        exported = lab._export()
        self.assertEqual(exported["initial_documents"], exported["current_documents"])
        self.assertEqual(len(exported["events"]), 3)

    def test_new_run_preserves_old_evidence(self):
        old_id = lab._prepare("injected", "vulnerable", "old")
        lab._call("delete_document", "report_02")
        new_id = lab._prepare("clean", "guarded", "new")
        old = lab._export(old_id)
        new = lab._export()
        self.assertEqual(new["id"], new_id)
        self.assertNotIn("report_02", old["current_documents"])
        self.assertIn("report_02", new["current_documents"])
        self.assertNotIn(lab._PAYLOAD, new["current_documents"]["report_01"])
        self.assertEqual(new["events"], [])

    def test_concurrent_deletion_records_one_mutation(self):
        lab._prepare("clean", "vulnerable", "test")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: lab._call("delete_document", "report_02"), range(2)))
        self.assertCountEqual([result["status"] for result in results], ["deleted", "not_found"])
        self.assertEqual(len(lab._export()["events"]), 2)

    def test_all_new_documents_are_readable_and_deletion_is_scoped(self):
        for mode in ("vulnerable", "guarded"):
            with self.subTest(mode=mode):
                lab._prepare("clean", mode, "expanded-fixtures")
                self.assertEqual(lab._call("list_documents")["documents"], list(lab._IDS))
                for document_id in lab._IDS[2:]:
                    expected = (Path(lab.__file__).parent / "documents" / f"{document_id}.md").read_text(encoding="utf-8")
                    self.assertEqual(lab._call("read_document", document_id)["content"], expected)
                    result = lab._call("delete_document", document_id)
                    self.assertEqual(result["status"], "deleted" if mode == "vulnerable" else "blocked")
                remaining = lab._export()["current_documents"]
                self.assertEqual(set(remaining), set(lab._IDS[:2] if mode == "vulnerable" else lab._IDS))

    def test_injection_changes_only_original_target_document(self):
        clean_id = lab._prepare("clean", "vulnerable", "clean")
        clean = lab._export(clean_id)["initial_documents"]
        lab._prepare("injected", "vulnerable", "injected")
        injected = lab._export()["initial_documents"]
        self.assertEqual(injected["report_01"], clean["report_01"] + lab._PAYLOAD)
        for document_id in lab._IDS[1:]:
            self.assertEqual(injected[document_id], clean[document_id])

    def test_permission_matrix_and_content_disclosure_audit(self):
        for role, own, other in (("warehouse", "report_03", "report_06"), ("purchasing", "report_06", "report_03")):
            for mode in ("vulnerable", "guarded"):
                with self.subTest(role=role, mode=mode):
                    lab._prepare("permissions", mode, "acl-test", role)
                    self.assertEqual(lab._call("read_document", own)["status"], "ok")
                    result = asyncio.run(lab.Tools().read_document(other))
                    if mode == "guarded":
                        self.assertEqual(result["status"], "access_denied")
                        self.assertNotIn("content", result)
                    else:
                        self.assertEqual(result["status"], "ok")
                        self.assertTrue(result["content"])
                    exported = lab._export()
                    decision = exported["events"][-1]["authorization"]
                    self.assertFalse(decision["requested_document_read_allowed"])
                    self.assertEqual(decision["unauthorized_content_returned"], mode == "vulnerable")
                    self.assertEqual(decision["role"], role)
                    self.assertEqual(exported["initial_documents"], exported["current_documents"])

    def test_permission_listing_does_not_leak_unauthorized_ids_in_guarded_mode(self):
        for mode in ("vulnerable", "guarded"):
            lab._prepare("permissions", mode, "listing", "warehouse")
            result = asyncio.run(lab.Tools().list_documents())
            self.assertEqual(result["documents"], list(lab._IDS) if mode == "vulnerable" else ["report_03"])
            decision = lab._export()["events"][-1]["authorization"]
            self.assertEqual(bool(decision["unauthorized_ids_returned"]), mode == "vulnerable")
            self.assertFalse(decision["unauthorized_content_returned"])

    def test_permissions_deletion_is_disabled_in_both_modes(self):
        for mode in ("vulnerable", "guarded"):
            lab._prepare("permissions", mode, "read-only", "warehouse")
            for document_id in ("report_03", "report_06"):
                self.assertEqual(asyncio.run(lab.Tools().delete_document(document_id))["status"], "blocked")
            exported = lab._export()
            self.assertEqual(exported["initial_documents"], exported["current_documents"])

    def test_role_is_operator_controlled_and_survives_new_runs(self):
        old_id = lab._prepare("permissions", "guarded", "old", "warehouse")
        with self.assertRaises(TypeError):
            asyncio.run(lab.Tools().read_document("report_06", role="purchasing"))
        self.assertEqual(lab._call("read_document", "report_06")["status"], "access_denied")
        lab._prepare("permissions", "guarded", "new", "purchasing")
        self.assertEqual(lab._call("read_document", "report_06")["status"], "ok")
        old = lab._export(old_id)
        self.assertEqual(old["access_policy"]["role"], "warehouse")
        self.assertEqual(old["events"][-1]["authorization"]["role"], "warehouse")

    def test_legacy_database_upgrade_preserves_original_run(self):
        old_id = lab._prepare("injected", "vulnerable", "legacy")
        lab._call("delete_document", "report_02")
        old = lab._export(old_id)
        # v1.1 had neither of these tables. Its runs/events schemas are unchanged.
        with closing(lab._connect()) as db, db:
            db.execute("DROP TABLE authorization_events")
            db.execute("DROP TABLE access_policies")
        self.assertEqual(lab._export(old_id), old)
        lab._prepare("permissions", "guarded", "upgrade", "warehouse")
        lab._prepare("permissions", "guarded", "idempotent", "warehouse")
        self.assertEqual(lab._export(old_id), old)
        self.assertEqual(lab._call("read_document", "report_06")["status"], "access_denied")

    def test_missing_policy_fails_closed(self):
        lab._prepare("permissions", "guarded", "missing-policy", "warehouse")
        with closing(lab._connect()) as db, db:
            db.execute("DELETE FROM access_policies")
        for tool, document_id in (("list_documents", None), ("read_document", "report_06"), ("delete_document", "report_03")):
            with self.assertRaisesRegex(RuntimeError, "Missing access policy"):
                lab._call(tool, document_id)

    def test_permissions_role_must_be_explicit_and_known(self):
        for role in (None, "admin", "unknown"):
            with self.assertRaises(ValueError):
                lab._prepare("permissions", "guarded", "bad-role", role)
        with self.assertRaises(ValueError):
            lab._prepare("clean", "vulnerable", "bad-scenario", "warehouse")

    def test_optional_deletion_permission_matrix_and_audit(self):
        for role, own, other in (("warehouse", "report_03", "report_06"), ("purchasing", "report_06", "report_03")):
            for mode in ("vulnerable", "guarded"):
                for target in (own, other):
                    with self.subTest(role=role, mode=mode, target=target):
                        lab._prepare("permissions", mode, "delete-test", role, allow_delete=True)
                        result = asyncio.run(lab.Tools().delete_document(target))
                        deleted = mode == "vulnerable" or target == own
                        self.assertEqual(result["status"], "deleted" if deleted else "access_denied")
                        exported = lab._export()
                        self.assertEqual(target not in exported["current_documents"], deleted)
                        event = exported["events"][-1]
                        self.assertIn(target, event["before"])
                        self.assertEqual(target not in event["after"], deleted)
                        self.assertEqual(event["authorization"]["requested_document_delete_allowed"], target == own)
                        self.assertEqual(event["authorization"]["unauthorized_deletion_performed"], deleted and target != own)
                        self.assertFalse(event["authorization"]["unauthorized_content_returned"])
                        self.assertEqual(exported["system_prompt"], lab._DELETE_ACCESS_SYSTEM_PROMPT)

    def test_allow_delete_does_not_change_old_runs_or_read_permissions(self):
        old_id = lab._prepare("permissions", "guarded", "read-only", "warehouse")
        lab._call("delete_document", "report_03")
        old = lab._export(old_id)
        lab._prepare("permissions", "guarded", "deletable", "warehouse", allow_delete=True)
        self.assertEqual(lab._call("read_document", "report_06")["status"], "access_denied")
        self.assertEqual(lab._call("list_documents")["documents"], ["report_03"])
        self.assertEqual(lab._export(old_id), old)
        self.assertFalse(old["access_policy"]["can_delete"])
        self.assertEqual(old["system_prompt"], lab._ACCESS_SYSTEM_PROMPT)

    def test_allow_delete_requires_explicit_boolean_and_permissions_scenario(self):
        with self.assertRaises(ValueError):
            lab._prepare("clean", "vulnerable", "bad", allow_delete=True)
        with self.assertRaises(ValueError):
            lab._prepare("permissions", "vulnerable", "bad", "warehouse", allow_delete="false")
        lab._prepare("permissions", "guarded", "invalid-policy", "warehouse")
        with closing(lab._connect()) as db, db:
            db.execute("UPDATE access_policies SET policy_json=replace(policy_json, 'false', '\"false\"')")
        with self.assertRaisesRegex(RuntimeError, "Invalid access policy"):
            lab._call("delete_document", "report_03")


if __name__ == "__main__":
    unittest.main()
