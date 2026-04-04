"""Regression tests for Git ref inference in the knowledge stage."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from app.schemas.fetched_page import FetchedPage
from app.schemas.knowledge import KnowledgeModel
from app.schemas.task import TaskModel
from app.stages.knowledge import (
    KnowledgeSourcesModel,
    KnowledgeStage,
    ReferenceRecord,
    extract_summary_candidate,
    heuristic_summary_from_pages,
    infer_git_refs,
    infer_vulnerability_type,
    should_follow_discovered_link,
)
from app.tools.patch_tools import PatchSummary


class InferGitRefsTests(unittest.TestCase):
    def test_vulnerable_ref_uses_fixed_commit_parent(self) -> None:
        osv_payload = {
            "references": [
                {"url": "https://github.com/lua/lua/commit/1f3c6f4534c6411313361697d98d1145a1f030fa"},
            ],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [
                                {"introduced": "c33b1728aeb7dfeec4013562660e07d32697aa6b"},
                                {"fixed": "1f3c6f4534c6411313361697d98d1145a1f030fa"},
                            ],
                        }
                    ]
                }
            ],
        }

        with patch(
            "app.stages.knowledge.fetch_github_parent_ref",
            return_value="25b143dd34fb587d1e35290c4b25bc08954800e2",
        ) as mocked_parent_lookup:
            vulnerable_ref, fixed_ref = infer_git_refs(
                osv_payload,
                fallback_fixed=None,
                fallback_vulnerable=None,
                repo_url="https://github.com/lua/lua.git",
            )

        self.assertEqual(fixed_ref, "1f3c6f4534c6411313361697d98d1145a1f030fa")
        self.assertEqual(vulnerable_ref, "25b143dd34fb587d1e35290c4b25bc08954800e2")
        mocked_parent_lookup.assert_called_once_with(
            "https://github.com/lua/lua.git",
            "1f3c6f4534c6411313361697d98d1145a1f030fa",
        )

    def test_vulnerable_ref_falls_back_when_parent_lookup_fails(self) -> None:
        osv_payload = {
            "references": [],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "GIT",
                            "events": [
                                {"fixed": "fixed-sha"},
                            ],
                        }
                    ]
                }
            ],
        }

        with patch("app.stages.knowledge.fetch_github_parent_ref", return_value=None):
            vulnerable_ref, fixed_ref = infer_git_refs(
                osv_payload,
                fallback_fixed=None,
                fallback_vulnerable="existing-vulnerable",
                repo_url="https://github.com/example/project.git",
            )

        self.assertEqual(fixed_ref, "fixed-sha")
        self.assertEqual(vulnerable_ref, "existing-vulnerable")

    def test_summary_prefers_advisory_description_over_commit_page_chrome(self) -> None:
        commit_page = FetchedPage(
            url="https://github.com/example/project/commit/abc123",
            title="Fix bug",
            html="",
            cleaned_text="Fix bug\nNavigation Menu\nToggle navigation\nPlatform\nSecurity\nPricing",
            status_code=200,
            content_type="text/html",
            local_path=None,
            links=[],
        )
        advisory_page = FetchedPage(
            url="https://github.com/example/project/security/advisories/GHSA-xxxx-yyyy-zzzz",
            title="Advisory",
            html="",
            cleaned_text=(
                "Advisory\n\nDescription\nNodes can publish ATXs which reference the incorrect previous "
                "ATX of the smesher, breaking the expected chain validation rule.\n\nImpact\n"
                "Attackers can abuse the stale reference to gain rewards."
            ),
            status_code=200,
            content_type="text/html",
            local_path=None,
            links=[],
        )

        summary = heuristic_summary_from_pages([commit_page, advisory_page])
        self.assertIn("reference the incorrect previous ATX", summary)
        self.assertEqual(infer_vulnerability_type(summary), "improper-input-validation")

    def test_summary_candidate_extracts_description_section(self) -> None:
        page = FetchedPage(
            url="https://nvd.nist.gov/vuln/detail/CVE-2024-34360",
            title="NVD",
            html="",
            cleaned_text=(
                "NVD - CVE-2024-34360\n\nDescription\n"
                "go-spacemesh allows an incorrect previous ATX reference, breaking protocol validation.\n\n"
                "Metrics\nCVSS 3.1"
            ),
            status_code=200,
            content_type="text/html",
            local_path=None,
            links=[],
        )

        self.assertEqual(
            extract_summary_candidate(page),
            "go-spacemesh allows an incorrect previous ATX reference, breaking protocol validation.",
        )

    def test_recursive_crawl_rejects_github_navigation_pages(self) -> None:
        parent = "https://github.com/example/project/commit/abc123"
        self.assertFalse(
            should_follow_discovered_link(parent, "https://github.com/security/advanced-security")
        )
        self.assertFalse(
            should_follow_discovered_link(parent, "https://github.com/login?return_to=%2Fexample%2Fproject")
        )
        self.assertTrue(
            should_follow_discovered_link(parent, "https://github.com/example/project/pull/42")
        )

    def test_llm_result_backfills_empty_heuristic_fields(self) -> None:
        task = TaskModel(
            task_id="CVE-TEST",
            cve_id="CVE-TEST",
            repo_url="https://github.com/example/project.git",
            vulnerable_ref="old-ref",
            fixed_ref="new-ref",
            references=[],
            reference_details=[],
        )
        source_registry = KnowledgeSourcesModel(
            cve_id="CVE-TEST",
            selected_references=[ReferenceRecord(url="https://example.com/advisory")],
        )
        fetched_pages = [
            FetchedPage(
                url="https://nvd.nist.gov/vuln/detail/CVE-TEST",
                title="NVD",
                html="",
                cleaned_text=(
                    "Description\nThe service does not validate the previous record correctly, "
                    "allowing a stale reference to bypass protocol checks."
                ),
                status_code=200,
                content_type="text/html",
                local_path=None,
                links=[],
            )
        ]
        patch_summaries = [
            PatchSummary(
                affected_files=["src/validator.go"],
                changed_functions=["func validatePreviousRecord() error"],
                summary="Patch touches 1 file(s).",
            )
        ]

        stage = KnowledgeStage()
        with patch.object(
            stage,
            "_try_llm_synthesis",
            return_value=KnowledgeModel(
                cve_id="CVE-TEST",
                summary="LLM summary",
                vulnerability_type="improper-input-validation",
                repo_url="",
                vulnerable_ref="",
                fixed_ref="",
                affected_files=[],
                reproduction_hints=[],
                expected_error_patterns=[],
                expected_stack_keywords=[],
                references=[],
            ),
        ):
            knowledge = stage.synthesize_knowledge(task, source_registry, fetched_pages, patch_summaries)

        self.assertEqual(knowledge.summary, "LLM summary")
        self.assertEqual(knowledge.affected_files, ["src/validator.go"])
        self.assertTrue(knowledge.reproduction_hints)
        self.assertEqual(knowledge.expected_stack_keywords, ["func validatePreviousRecord() error"])
        self.assertEqual(knowledge.references, ["https://example.com/advisory"])


if __name__ == "__main__":
    unittest.main()
