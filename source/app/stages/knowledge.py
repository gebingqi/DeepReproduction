"""Standalone knowledge agent implementation."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from app.config import build_chat_model, load_app_config
from app.schemas.fetched_page import FetchedPage
from app.schemas.knowledge import KnowledgeModel
from app.schemas.task import TaskModel, TaskReference
from app.tools.archive_tools import ArchiveTool
from app.tools.content_cleaner import ContentCleaner
from app.tools.patch_tools import PatchSummary, PatchTool
from app.tools.reference_extractor import ReferenceExtractor
from app.tools.web_fetch import WebFetchTool


class ReferenceRecord(BaseModel):
    """Single reference tracked by the knowledge stage."""

    url: str = Field(..., description="Reference URL.")
    source_type: str = Field(default="reference", description="High-level source type.")
    priority: str = Field(default="P2", description="Priority level assigned by heuristics.")
    depth: int = Field(default=0, description="Traversal depth.")
    selected: bool = Field(default=True, description="Whether the reference was kept.")
    note: str = Field(default="", description="Short decision note.")
    reference_kind: str = Field(default="", description="Original reference type such as FIX or EVIDENCE.")


class KnowledgeSourcesModel(BaseModel):
    """Registry of sources considered by the knowledge stage."""

    cve_id: str = Field(..., description="CVE identifier.")
    osv_url: str = Field(default="", description="OSV endpoint used for bootstrap.")
    seed_references: List[ReferenceRecord] = Field(default_factory=list, description="Initial references.")
    selected_references: List[ReferenceRecord] = Field(default_factory=list, description="References kept for evidence collection.")
    skipped_references: List[ReferenceRecord] = Field(default_factory=list, description="References dropped during filtering.")
    local_evidence_files: List[str] = Field(default_factory=list, description="Local evidence files created by this stage.")


class ExtractedPoc(BaseModel):
    """Structured PoC candidate extracted from evidence."""

    has_poc: bool = Field(default=False, description="Whether the evidence contains an explicit PoC or reproducer.")
    filename: str = Field(default="poc.txt", description="Suggested PoC filename.")
    content: str = Field(default="", description="PoC or reproduction script content.")
    rationale: str = Field(default="", description="Short explanation for the extraction decision.")


@dataclass(frozen=True)
class KnowledgePaths:
    """Filesystem layout owned by the knowledge stage."""

    cve_root: Path
    yaml_dir: Path
    evidence_dir: Path
    raw_dir: Path
    cleaned_dir: Path
    extracted_dir: Path
    diff_dir: Path
    pocs_dir: Path
    task_yaml: Path
    knowledge_yaml: Path
    runtime_state_yaml: Path
    knowledge_sources_yaml: Path
    patch_diff: Path


def build_knowledge_paths(cve_id: str, dataset_root: str = "Dataset") -> KnowledgePaths:
    """Resolve the dataset layout for the standalone knowledge stage."""

    cve_root = Path(dataset_root) / cve_id
    yaml_dir = cve_root / "vuln_yaml"
    evidence_dir = cve_root / "vuln_data" / "knowledge_sources"
    diff_dir = cve_root / "vuln_data" / "vuln_diffs"
    pocs_dir = cve_root / "vuln_data" / "vuln_pocs"

    return KnowledgePaths(
        cve_root=cve_root,
        yaml_dir=yaml_dir,
        evidence_dir=evidence_dir,
        raw_dir=evidence_dir / "raw",
        cleaned_dir=evidence_dir / "cleaned",
        extracted_dir=evidence_dir / "extracted",
        diff_dir=diff_dir,
        pocs_dir=pocs_dir,
        task_yaml=yaml_dir / "task.yaml",
        knowledge_yaml=yaml_dir / "knowledge.yaml",
        runtime_state_yaml=yaml_dir / "runtime_state.yaml",
        knowledge_sources_yaml=yaml_dir / "knowledge_sources.yaml",
        patch_diff=diff_dir / "patch.diff",
    )


class KnowledgeStage:
    """Knowledge-stage agent."""

    _USER_AGENT = "DeepReproductionKnowledgeAgent/1.0"

    def __init__(self) -> None:
        self.reference_extractor = ReferenceExtractor()
        self.fetcher = WebFetchTool()
        self.cleaner = ContentCleaner()
        self.archives = ArchiveTool()
        self.patches = PatchTool()
        runtime = load_app_config().runtime
        self.max_reference_depth = runtime.knowledge_max_reference_depth
        self.max_fetch_count = runtime.knowledge_max_fetch_count
        self.fetch_timeout_seconds = runtime.knowledge_fetch_timeout_seconds
        self.enable_llm_curation = runtime.knowledge_enable_llm_curation
        self.last_llm_status = "disabled"
        self.last_llm_error: Optional[str] = None

    def run(self, cve_id: str, dataset_root: str = "Dataset") -> KnowledgeModel:
        """Run the full standalone knowledge-stage workflow."""

        paths = build_knowledge_paths(cve_id=cve_id, dataset_root=dataset_root)
        prepare_layout(paths)

        try:
            task, bootstrap_error = self.bootstrap_task(cve_id=cve_id, paths=paths)
            reset_stage_outputs(paths)
            write_yaml(paths.task_yaml, task.model_dump(mode="json"))

            selected_references, skipped_references = self.prioritize_references(
                task.references,
                task.reference_details,
            )
            (
                fetched_pages,
                local_evidence_files,
                patch_summaries,
                selected_references,
                skipped_references,
            ) = self.collect_evidence(selected_references, skipped_references, paths)
            ensure_empty_file(paths.patch_diff)

            source_registry = KnowledgeSourcesModel(
                cve_id=task.cve_id,
                osv_url=task.cve_url or "",
                seed_references=[
                    ReferenceRecord(
                        url=url,
                        source_type=guess_source_type(url),
                        priority=score_reference(url, reference_type=reference_type_for_url(task.reference_details, url)),
                        note="Seed reference from task input or OSV bootstrap.",
                        reference_kind=reference_type_for_url(task.reference_details, url) or "",
                    )
                    for url in dedupe_preserve_order(task.references)
                ],
                selected_references=selected_references,
                skipped_references=skipped_references,
                local_evidence_files=local_evidence_files,
            )
            write_yaml(paths.knowledge_sources_yaml, source_registry.model_dump(mode="json"))

            if bootstrap_error and not task.references:
                raise RuntimeError(f"Failed to bootstrap references from OSV: {bootstrap_error}")

            if not fetched_pages and not patch_summaries and not local_evidence_files:
                if selected_references:
                    failed_urls = ", ".join(record.url for record in selected_references[:5])
                    raise RuntimeError(f"Failed to fetch any evidence from selected references. First targets: {failed_urls}")
                raise RuntimeError("Knowledge stage produced no references and no evidence.")

            knowledge = self.synthesize_knowledge(
                task=task,
                source_registry=source_registry,
                fetched_pages=fetched_pages,
                patch_summaries=patch_summaries,
            )
            write_yaml(paths.knowledge_yaml, knowledge.model_dump(mode="json"))
            self.extract_and_write_poc(
                task=task,
                fetched_pages=fetched_pages,
                patch_summaries=patch_summaries,
                paths=paths,
            )
            write_yaml(
                paths.runtime_state_yaml,
                build_runtime_state_payload(
                    task_id=task.cve_id,
                    success=True,
                    message="Knowledge stage completed successfully.",
                    llm_status=self.last_llm_status,
                    llm_error=self.last_llm_error,
                ),
            )
            return knowledge
        except Exception as error:
            write_yaml(
                paths.runtime_state_yaml,
                build_runtime_state_payload(
                    task_id=cve_id,
                    success=False,
                    message=str(error),
                    llm_status=self.last_llm_status,
                    llm_error=self.last_llm_error,
                ),
            )
            raise

    def bootstrap_task(self, cve_id: str, paths: KnowledgePaths) -> tuple[TaskModel, Optional[str]]:
        """Create or refresh a task model from local YAML and OSV metadata."""

        base_task = self._load_existing_task(paths.task_yaml, cve_id)
        try:
            osv_payload = self._fetch_osv(cve_id)
        except Exception as error:
            return base_task, str(error)
        if not osv_payload:
            return base_task, "OSV returned an empty payload."
        return self._merge_osv_into_task(base_task, osv_payload), None

    def prioritize_references(
        self,
        references: Iterable[str],
        reference_details: Optional[Iterable[TaskReference]] = None,
    ) -> tuple[List[ReferenceRecord], List[ReferenceRecord]]:
        """Prioritize references and produce a bounded crawl queue."""

        selected: List[ReferenceRecord] = []
        skipped: List[ReferenceRecord] = []
        reference_type_map = build_reference_type_map(reference_details or [])

        normalized = self.reference_extractor.normalize(references)
        filtered = set(self.reference_extractor.filter_relevant(normalized))

        for url in normalized:
            reference_type = reference_type_map.get(url)
            if url not in filtered:
                skipped.append(
                    ReferenceRecord(
                        url=url,
                        source_type=guess_source_type(url),
                        priority="P3",
                        selected=False,
                        note="Dropped by domain filter.",
                        reference_kind=reference_type or "",
                    )
                )
                continue

            priority = score_reference(url, reference_type=reference_type)
            record = ReferenceRecord(
                url=url,
                source_type=guess_source_type(url),
                priority=priority,
                depth=0,
                selected=priority != "P3",
                note="Selected by deterministic URL heuristics." if priority != "P3" else "Skipped by deterministic URL heuristics.",
                reference_kind=reference_type or "",
            )
            if record.selected:
                selected.append(record)
                for derived in derive_reference_variants(url):
                    selected.append(
                        ReferenceRecord(
                            url=derived,
                            source_type=guess_source_type(derived),
                            priority="P0",
                            depth=0,
                            selected=True,
                            note="Derived patch-style variant from selected reference.",
                            reference_kind=reference_type or "",
                        )
                    )
            else:
                skipped.append(record)

        dedup_selected = dedupe_reference_records(selected)
        selected_urls = {item.url for item in dedup_selected}
        dedup_skipped = [record for record in dedupe_reference_records(skipped) if record.url not in selected_urls]
        return dedup_selected, dedup_skipped

    def collect_evidence(
        self,
        selected_references: List[ReferenceRecord],
        skipped_references: List[ReferenceRecord],
        paths: KnowledgePaths,
    ) -> tuple[List[FetchedPage], List[str], List[PatchSummary], List[ReferenceRecord], List[ReferenceRecord]]:
        """Fetch selected references, recursively expand links, and persist evidence files."""

        fetched_pages: list[FetchedPage] = []
        evidence_files: list[str] = []
        patch_summaries: list[PatchSummary] = []

        selected_by_url = {record.url: record for record in selected_references}
        skipped_by_url = {record.url: record for record in skipped_references}
        queue: list[ReferenceRecord] = list(selected_references)
        fetched_urls: set[str] = set()

        while queue and len(fetched_urls) < self.max_fetch_count:
            record = queue.pop(0)
            if record.url in fetched_urls:
                continue
            fetched_urls.add(record.url)

            try:
                fetched = self.fetcher.fetch_one(
                    record.url,
                    download_dir=str(paths.raw_dir),
                    timeout=self.fetch_timeout_seconds,
                )
            except Exception as error:
                record.note = f"{record.note} Fetch failed: {error}"
                continue

            fetched_pages.append(fetched)

            if fetched.local_path:
                evidence_files.append(fetched.local_path)
                if self.archives.is_supported_archive(fetched.local_path):
                    extracted_dir = paths.extracted_dir / sanitize_filename(Path(fetched.local_path).stem)
                    extraction = self.archives.extract(fetched.local_path, str(extracted_dir))
                    evidence_files.extend(extraction.extracted_files)
                    continue

            if fetched.html:
                if looks_like_patch(record.url, fetched.content_type, fetched.html):
                    patch_summary = self.patches.parse_diff(fetched.html)
                    patch_summaries.append(patch_summary)
                    if record.url.lower().endswith(".diff") and (
                        not paths.patch_diff.exists() or not paths.patch_diff.read_text(encoding="utf-8").strip()
                    ):
                        paths.patch_diff.write_text(fetched.html, encoding="utf-8")
                        evidence_files.append(str(paths.patch_diff))
                    else:
                        patch_file = paths.raw_dir / f"{sanitize_filename(record.url)}.patch"
                        patch_file.write_text(fetched.html, encoding="utf-8")
                        evidence_files.append(str(patch_file))
                else:
                    cleaned = self.cleaner.clean_html(fetched.html, source_url=fetched.url) if fetched.content_type == "text/html" else self.cleaner.clean_markdown(fetched.html, source_url=fetched.url)
                    cleaned = self.cleaner.trim_for_prompt(cleaned, max_chars=12000)
                    fetched.cleaned_text = cleaned.cleaned_text
                    if cleaned.title and not fetched.title:
                        fetched.title = cleaned.title
                    cleaned_path = paths.cleaned_dir / f"{sanitize_filename(record.url)}.md"
                    cleaned_path.write_text(render_cleaned_markdown(fetched.url, cleaned.title, cleaned.cleaned_text), encoding="utf-8")
                    evidence_files.append(str(cleaned_path))

                    discovered_selected, discovered_skipped = self.discover_child_references(
                        parent=record,
                        child_links=fetched.links,
                        selected_by_url=selected_by_url,
                        skipped_by_url=skipped_by_url,
                    )
                    for child_record in discovered_selected:
                        selected_by_url[child_record.url] = child_record
                        if child_record.url not in fetched_urls:
                            queue.append(child_record)
                    for child_record in discovered_skipped:
                        if child_record.url not in selected_by_url:
                            skipped_by_url[child_record.url] = child_record

        return (
            fetched_pages,
            dedupe_preserve_order(evidence_files),
            patch_summaries,
            list(selected_by_url.values()),
            list(skipped_by_url.values()),
        )

    def discover_child_references(
        self,
        parent: ReferenceRecord,
        child_links: Iterable[str],
        selected_by_url: dict[str, ReferenceRecord],
        skipped_by_url: dict[str, ReferenceRecord],
    ) -> tuple[List[ReferenceRecord], List[ReferenceRecord]]:
        """Discover and classify child references from a fetched page."""

        if parent.depth >= self.max_reference_depth:
            return [], []

        discovered_selected: list[ReferenceRecord] = []
        discovered_skipped: list[ReferenceRecord] = []

        normalized_links = self.reference_extractor.normalize(child_links)
        filtered_links = self.reference_extractor.filter_relevant(normalized_links)

        for url in filtered_links:
            if url in selected_by_url or url in skipped_by_url:
                continue
            if not should_follow_discovered_link(parent.url, url):
                discovered_skipped.append(
                    ReferenceRecord(
                        url=url,
                        source_type=guess_source_type(url),
                        priority="P3",
                        depth=parent.depth + 1,
                        selected=False,
                        note=f"Discovered from {parent.url} but filtered by recursive crawl rules.",
                    )
                )
                continue

            priority = score_reference(url)
            if priority == "P3":
                discovered_skipped.append(
                    ReferenceRecord(
                        url=url,
                        source_type=guess_source_type(url),
                        priority=priority,
                        depth=parent.depth + 1,
                        selected=False,
                        note=f"Discovered from {parent.url} but scored too low for recursive crawl.",
                    )
                )
                continue

            record = ReferenceRecord(
                url=url,
                source_type=guess_source_type(url),
                priority=priority,
                depth=parent.depth + 1,
                selected=True,
                note=f"Discovered recursively from {parent.url}.",
            )
            discovered_selected.append(record)

            for derived in derive_reference_variants(url):
                if derived in selected_by_url or derived in skipped_by_url:
                    continue
                discovered_selected.append(
                    ReferenceRecord(
                        url=derived,
                        source_type=guess_source_type(derived),
                        priority="P0",
                        depth=parent.depth + 1,
                        selected=True,
                        note=f"Derived patch-style variant from recursively discovered URL {url}.",
                    )
                )

        return dedupe_reference_records(discovered_selected), dedupe_reference_records(discovered_skipped)

    def synthesize_knowledge(
        self,
        task: TaskModel,
        source_registry: KnowledgeSourcesModel,
        fetched_pages: List[FetchedPage],
        patch_summaries: List[PatchSummary],
    ) -> KnowledgeModel:
        """Synthesize the final `knowledge.yaml` record."""

        summary_source = heuristic_summary_from_pages(fetched_pages)
        heuristic_vuln_type = infer_vulnerability_type(summary_source)
        heuristic_affected_files = dedupe_preserve_order(item for patch in patch_summaries for item in patch.affected_files)
        heuristic_reproduction_hints = build_reproduction_hints(task, fetched_pages, patch_summaries)
        heuristic_expected_stack_keywords = extract_stack_keywords(patch_summaries)
        llm_result = self._try_llm_synthesis(task, fetched_pages, patch_summaries)
        if llm_result is not None:
            llm_result.summary = llm_result.summary or summary_source
            llm_result.vulnerability_type = llm_result.vulnerability_type or heuristic_vuln_type
            llm_result.references = [record.url for record in source_registry.selected_references]
            llm_result.repo_url = llm_result.repo_url or task.repo_url
            llm_result.vulnerable_ref = llm_result.vulnerable_ref or task.vulnerable_ref
            llm_result.fixed_ref = llm_result.fixed_ref or task.fixed_ref
            llm_result.affected_files = llm_result.affected_files or heuristic_affected_files
            llm_result.reproduction_hints = llm_result.reproduction_hints or heuristic_reproduction_hints
            llm_result.expected_stack_keywords = llm_result.expected_stack_keywords or heuristic_expected_stack_keywords
            llm_result.expected_error_patterns = llm_result.expected_error_patterns or default_error_patterns(
                llm_result.vulnerability_type or heuristic_vuln_type
            )
            return llm_result

        return KnowledgeModel(
            cve_id=task.cve_id,
            summary=summary_source,
            vulnerability_type=heuristic_vuln_type,
            repo_url=task.repo_url,
            vulnerable_ref=task.vulnerable_ref,
            fixed_ref=task.fixed_ref,
            affected_files=heuristic_affected_files,
            reproduction_hints=heuristic_reproduction_hints,
            expected_error_patterns=default_error_patterns(heuristic_vuln_type),
            expected_stack_keywords=heuristic_expected_stack_keywords,
            references=[record.url for record in source_registry.selected_references],
        )

    def _try_llm_synthesis(
        self,
        task: TaskModel,
        fetched_pages: List[FetchedPage],
        patch_summaries: List[PatchSummary],
    ) -> Optional[KnowledgeModel]:
        """Try JSON-based LLM synthesis using plain text output."""

        if not self.enable_llm_curation:
            self.last_llm_status = "disabled"
            self.last_llm_error = None
            return None

        evidence_blocks: list[str] = []
        for page in fetched_pages[:8]:
            if not page.cleaned_text:
                continue
            evidence_blocks.append("\n".join([f"URL: {page.url}", f"Title: {page.title}", "Content:", page.cleaned_text[:4000]]))

        for patch in patch_summaries[:5]:
            evidence_blocks.append(
                "\n".join(
                    [
                        "Patch summary:",
                        patch.summary,
                        f"Affected files: {', '.join(patch.affected_files)}",
                        f"Changed functions: {', '.join(patch.changed_functions)}",
                    ]
                )
            )

        if not evidence_blocks:
            self.last_llm_status = "skipped_no_evidence"
            self.last_llm_error = None
            return None

        prompt = "\n\n".join(
            [
                "You are a security research assistant.",
                "Extract a compact structured knowledge record for the CVE.",
                "Only include facts supported by the evidence.",
                "Return exactly one JSON object and no markdown fences.",
                "Use this schema:",
                json.dumps(
                    {
                        "cve_id": "string",
                        "summary": "string",
                        "vulnerability_type": "string",
                        "repo_url": "string or null",
                        "vulnerable_ref": "string or null",
                        "fixed_ref": "string or null",
                        "affected_files": ["string"],
                        "reproduction_hints": ["string"],
                        "expected_error_patterns": ["string"],
                        "expected_stack_keywords": ["string"],
                        "references": ["string"],
                    },
                    ensure_ascii=True,
                ),
                f"CVE: {task.cve_id}",
                f"Repository: {task.repo_url or ''}",
                f"Vulnerable ref: {task.vulnerable_ref or ''}",
                f"Fixed ref: {task.fixed_ref or ''}",
                "Evidence:",
                "\n\n---\n\n".join(evidence_blocks),
            ]
        )

        try:
            model = build_chat_model("knowledge_agent", temperature=0)
            response = model.invoke(
                [
                    SystemMessage(content="You return strict JSON only."),
                    HumanMessage(content=prompt),
                ]
            )
            content = getattr(response, "content", response)
            parsed = parse_llm_json_payload(content)
            if parsed is None:
                self.last_llm_status = "unexpected_response"
                self.last_llm_error = "LLM response was not valid JSON."
                return None
            self.last_llm_status = "success"
            self.last_llm_error = None
            return KnowledgeModel(**parsed)
        except Exception as error:
            self.last_llm_status = "failed"
            self.last_llm_error = str(error)
            return None
        return None

    def _load_existing_task(self, task_yaml: Path, cve_id: str) -> TaskModel:
        if task_yaml.exists():
            payload = read_yaml(task_yaml)
            details = payload.get("reference_details") or []
            if not details and payload.get("references"):
                payload["reference_details"] = [{"url": url, "type": None} for url in payload.get("references", [])]
            return TaskModel(**payload)

        return TaskModel(
            task_id=cve_id,
            cve_id=cve_id,
            cve_url=f"https://api.osv.dev/v1/vulns/{cve_id}",
            references=[],
            reference_details=[],
        )

    def _fetch_osv(self, cve_id: str) -> dict:
        url = f"https://api.osv.dev/v1/vulns/{cve_id}"
        request = Request(url, headers={"User-Agent": self._USER_AGENT})
        with urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="replace")
        return json.loads(raw)

    def _merge_osv_into_task(self, task: TaskModel, osv_payload: dict) -> TaskModel:
        references = list(task.references)
        reference_details = [TaskReference(**item.model_dump(mode="json")) for item in task.reference_details]
        for item in osv_payload.get("references", []):
            url = item.get("url")
            if url:
                references.append(url)
                reference_details.append(TaskReference(url=url, type=item.get("type")))

        task_data = task.model_dump(mode="json")
        task_data["cve_url"] = task.cve_url or f"https://api.osv.dev/v1/vulns/{task.cve_id}"
        task_data["references"] = dedupe_preserve_order(references)
        task_data["reference_details"] = dedupe_task_references(reference_details)

        language = task.language or infer_language(osv_payload)
        repo_url = task.repo_url or infer_repo_url(osv_payload)
        vulnerable_ref, fixed_ref = infer_git_refs(
            osv_payload,
            fallback_fixed=task.fixed_ref,
            fallback_vulnerable=task.vulnerable_ref,
            repo_url=repo_url,
        )

        if repo_url:
            task_data["repo_url"] = repo_url
        if language:
            task_data["language"] = language
        if vulnerable_ref:
            task_data["vulnerable_ref"] = vulnerable_ref
        if fixed_ref:
            task_data["fixed_ref"] = fixed_ref

        return TaskModel(**task_data)

    def extract_and_write_poc(
        self,
        task: TaskModel,
        fetched_pages: List[FetchedPage],
        patch_summaries: List[PatchSummary],
        paths: KnowledgePaths,
    ) -> Optional[Path]:
        """Use the model to detect and persist an explicit PoC when present."""

        if not self.enable_llm_curation:
            return None

        poc_candidate = self._try_llm_poc_extraction(task, fetched_pages, patch_summaries)
        if poc_candidate is None or not poc_candidate.has_poc or not poc_candidate.content.strip():
            return None

        filename = poc_candidate.filename.strip() or "poc.txt"
        filename = sanitize_filename(filename)
        if "." not in filename:
            filename = f"{filename}.txt"
        poc_path = paths.pocs_dir / filename
        poc_path.write_text(poc_candidate.content.rstrip() + "\n", encoding="utf-8")
        return poc_path

    def _try_llm_poc_extraction(
        self,
        task: TaskModel,
        fetched_pages: List[FetchedPage],
        patch_summaries: List[PatchSummary],
    ) -> Optional[ExtractedPoc]:
        """Ask the model whether the evidence contains an explicit PoC."""

        evidence_blocks: list[str] = []
        for page in fetched_pages[:10]:
            if not page.cleaned_text:
                continue
            text = page.cleaned_text
            lowered = text.lower()
            if any(token in lowered for token in ("poc", "proof of concept", "reproduce", "reproducer", "payload", "pcall(", "_env", "```", "assert(", "base64")):
                evidence_blocks.append("\n".join([f"URL: {page.url}", f"Title: {page.title}", "Content:", text[:5000]]))

        if not evidence_blocks and patch_summaries:
            for patch in patch_summaries[:3]:
                evidence_blocks.append(
                    "\n".join(
                        [
                            "Patch summary:",
                            patch.summary,
                            f"Affected files: {', '.join(patch.affected_files)}",
                            f"Changed functions: {', '.join(patch.changed_functions)}",
                        ]
                    )
                )

        if not evidence_blocks:
            return None

        prompt = "\n\n".join(
            [
                "You are a security research assistant.",
                "Determine whether the evidence contains an explicit proof-of-concept, reproducer, runnable script, shell command sequence, or directly reconstructable payload.",
                "Only return has_poc=true when the evidence is explicit enough to save as a file.",
                "If no explicit PoC is present, return has_poc=false and empty content.",
                "Return exactly one JSON object and no markdown fences.",
                "Use this schema:",
                json.dumps(
                    {
                        "has_poc": "boolean",
                        "filename": "string",
                        "content": "string",
                        "rationale": "string",
                    },
                    ensure_ascii=True,
                ),
                f"CVE: {task.cve_id}",
                "Evidence:",
                "\n\n---\n\n".join(evidence_blocks),
            ]
        )

        try:
            model = build_chat_model("knowledge_agent", temperature=0)
            response = model.invoke(
                [
                    SystemMessage(content="You return strict JSON only."),
                    HumanMessage(content=prompt),
                ]
            )
            content = getattr(response, "content", response)
            parsed = parse_llm_json_payload(content)
            if parsed is None:
                return None
            return ExtractedPoc(**parsed)
        except Exception:
            return None


def run_knowledge_agent(cve_id: str, dataset_root: str = "Dataset") -> KnowledgeModel:
    """Public function called directly by the top-level controller."""

    return KnowledgeStage().run(cve_id=cve_id, dataset_root=dataset_root)


def knowledge_node(state):
    """Optional LangGraph adapter kept for compatibility."""

    task = state["task"]
    knowledge = run_knowledge_agent(cve_id=task.cve_id)
    history = list(state.get("stage_history", []))
    history.append({"stage": "knowledge", "status": "success"})
    return {
        "knowledge": knowledge,
        "current_stage": "build",
        "stage_history": history,
        "last_error": None,
    }


def prepare_layout(paths: KnowledgePaths) -> None:
    """Create directories owned by the knowledge stage."""

    paths.yaml_dir.mkdir(parents=True, exist_ok=True)
    paths.evidence_dir.mkdir(parents=True, exist_ok=True)
    paths.raw_dir.mkdir(parents=True, exist_ok=True)
    paths.cleaned_dir.mkdir(parents=True, exist_ok=True)
    paths.extracted_dir.mkdir(parents=True, exist_ok=True)
    paths.diff_dir.mkdir(parents=True, exist_ok=True)
    paths.pocs_dir.mkdir(parents=True, exist_ok=True)


def reset_stage_outputs(paths: KnowledgePaths) -> None:
    """Clear stage-owned outputs before writing a fresh run."""

    for directory in (paths.raw_dir, paths.cleaned_dir, paths.extracted_dir, paths.diff_dir, paths.pocs_dir):
        if not directory.exists():
            continue
        for child in directory.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()

    for path in (paths.knowledge_yaml, paths.runtime_state_yaml, paths.knowledge_sources_yaml):
        if path.exists():
            path.unlink()


def build_runtime_state_payload(
    task_id: str,
    success: bool,
    message: str,
    llm_status: str = "disabled",
    llm_error: Optional[str] = None,
) -> dict:
    """Build a runtime-state payload for the knowledge stage."""

    return {
        "task_id": task_id,
        "current_stage": "knowledge",
        "retry_count": {},
        "stage_history": [{"stage": "knowledge", "status": "success" if success else "failed"}],
        "last_error": None if success else message,
        "llm_status": llm_status,
        "llm_error": llm_error,
        "workspace": f"workspaces/{task_id}",
        "final_status": "success" if success else "failed",
    }


def read_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file) or {}


def write_yaml(path: Path, payload: dict) -> None:
    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(payload, file, sort_keys=False, allow_unicode=True)


def render_cleaned_markdown(url: str, title: str, cleaned_text: str) -> str:
    heading = title or url
    return f"# {heading}\n\nSource: {url}\n\n{cleaned_text}\n"


def sanitize_filename(value: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    return sanitized[:180].strip("._") or "artifact"


def ensure_empty_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text("", encoding="utf-8")


def dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen = set()
    ordered: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def dedupe_reference_records(records: Iterable[ReferenceRecord]) -> List[ReferenceRecord]:
    seen = set()
    ordered: list[ReferenceRecord] = []
    for record in records:
        if record.url in seen:
            continue
        seen.add(record.url)
        ordered.append(record)
    return ordered


def dedupe_task_references(records: Iterable[TaskReference]) -> List[dict]:
    extractor = ReferenceExtractor()
    seen = set()
    ordered: list[dict] = []
    for record in records:
        normalized = extractor.normalize([record.url])
        normalized_url = normalized[0] if normalized else record.url
        if normalized_url in seen:
            continue
        seen.add(normalized_url)
        ordered.append({"url": normalized_url, "type": record.type})
    return ordered


def score_reference(url: str, reference_type: Optional[str] = None) -> str:
    normalized_type = (reference_type or "").upper()
    if normalized_type in {"FIX", "EVIDENCE"}:
        return "P0"

    lowered = url.lower()
    if ".diff" in lowered or ".patch" in lowered or "/commit/" in lowered or "/commits/" in lowered:
        return "P0"
    if "/pull/" in lowered or "/issues/" in lowered or "advisory" in lowered or "security" in lowered:
        return "P1"
    if "osv.dev" in lowered or "nvd.nist.gov" in lowered or "lists." in lowered:
        return "P2"
    return "P3"


def build_reference_type_map(reference_details: Iterable[TaskReference]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    extractor = ReferenceExtractor()
    for item in reference_details:
        normalized = extractor.normalize([item.url])
        if normalized:
            mapping[normalized[0]] = (item.type or "").upper()
    return mapping


def reference_type_for_url(reference_details: Iterable[TaskReference], url: str) -> Optional[str]:
    return build_reference_type_map(reference_details).get(url)


def guess_source_type(url: str) -> str:
    lowered = url.lower()
    if ".diff" in lowered:
        return "diff"
    if ".patch" in lowered:
        return "patch"
    if "/commit/" in lowered or "/commits/" in lowered:
        return "commit"
    if "/pull/" in lowered:
        return "pull_request"
    if "/issues/" in lowered:
        return "issue"
    if "osv.dev" in lowered:
        return "osv"
    if "nvd.nist.gov" in lowered:
        return "nvd"
    return "reference"


def derive_reference_variants(url: str) -> List[str]:
    lowered = url.lower()
    variants: list[str] = []
    if "github.com" in lowered and "/commit/" in lowered and not lowered.endswith(".diff"):
        variants.append(f"{url}.diff")
    return variants


def should_follow_discovered_link(parent_url: str, child_url: str) -> bool:
    parent_parts = urlsplit(parent_url)
    child_parts = urlsplit(child_url)

    if child_parts.scheme not in {"http", "https"}:
        return False

    lowered = child_url.lower()
    if any(token in lowered for token in ("/login", "/signup", "/search", "/features", "/marketplace")):
        return False

    blocked_suffixes = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".css",
        ".js",
        ".woff",
        ".woff2",
        ".mp4",
        ".mp3",
    )
    lowered_path = child_parts.path.lower()
    if lowered_path.endswith(blocked_suffixes):
        return False

    if "nvd.nist.gov" in parent_parts.netloc.lower():
        return any(
            signal in lowered
            for signal in (
                "/vuln/detail/cve-",
                "/security/advisories/",
                "/commit/",
                ".diff",
                ".patch",
                "github.com",
                "gitlab.com",
            )
        )

    if "lists.fedoraproject.org" in child_parts.netloc.lower():
        return "/message/" in lowered or "cve-" in lowered

    if "github.com" in parent_parts.netloc.lower() and "github.com" in child_parts.netloc.lower():
        parent_repo = [segment for segment in parent_parts.path.split("/") if segment][:2]
        child_repo = [segment for segment in child_parts.path.split("/") if segment][:2]
        if len(parent_repo) == 2 and parent_repo == child_repo:
            return score_reference(child_url) in {"P0", "P1"}
        return "/security/advisories/" in lowered and score_reference(child_url) in {"P0", "P1"}

    if child_parts.netloc == parent_parts.netloc:
        return True

    if "github.com" in lowered or "gitlab.com" in lowered:
        return score_reference(child_url) in {"P0", "P1"}
    if "advisory" in lowered or "security" in lowered or "cve-" in lowered:
        return True
    if score_reference(child_url) in {"P0", "P1", "P2"}:
        return True

    return False


def looks_like_patch(url: str, content_type: str, body: str) -> bool:
    lowered_url = url.lower()
    if lowered_url.endswith(".patch") or lowered_url.endswith(".diff"):
        return True
    if content_type in {"text/plain", "text/x-diff"} and ("diff --git" in body or body.startswith("From ")):
        return True
    return False


def infer_language(osv_payload: dict) -> Optional[str]:
    ecosystem = (((osv_payload.get("affected") or [{}])[0]).get("package") or {}).get("ecosystem", "")
    mapping = {
        "PyPI": "Python",
        "Go": "Go",
        "Maven": "Java",
        "npm": "JavaScript",
        "crates.io": "Rust",
    }
    return mapping.get(ecosystem)


def infer_repo_url(osv_payload: dict) -> Optional[str]:
    for item in osv_payload.get("references", []):
        url = item.get("url", "")
        if "github.com" in url and "/commit/" in url:
            parts = urlsplit(url)
            path_parts = [segment for segment in parts.path.split("/") if segment]
            if len(path_parts) >= 2:
                return f"{parts.scheme}://{parts.netloc}/{path_parts[0]}/{path_parts[1]}.git"
    return None


def extract_github_repo_slug(repo_url: Optional[str]) -> Optional[str]:
    if not repo_url:
        return None

    parts = urlsplit(repo_url)
    if "github.com" not in parts.netloc.lower():
        return None

    path_parts = [segment for segment in parts.path.split("/") if segment]
    if len(path_parts) < 2:
        return None

    owner = path_parts[0]
    repo = path_parts[1].removesuffix(".git")
    if not owner or not repo:
        return None
    return f"{owner}/{repo}"


def fetch_github_parent_ref(repo_url: Optional[str], commit_ref: Optional[str]) -> Optional[str]:
    repo_slug = extract_github_repo_slug(repo_url)
    if not repo_slug or not commit_ref:
        return None

    request = Request(
        f"https://api.github.com/repos/{repo_slug}/commits/{commit_ref}",
        headers={
            "User-Agent": KnowledgeStage._USER_AGENT,
            "Accept": "application/vnd.github+json",
        },
    )
    try:
        with urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except Exception:
        return None

    parents = payload.get("parents") or []
    if not parents:
        return None

    first_parent = parents[0]
    if not isinstance(first_parent, dict):
        return None
    parent_sha = first_parent.get("sha")
    return parent_sha if isinstance(parent_sha, str) and parent_sha else None


def infer_git_refs(
    osv_payload: dict,
    fallback_fixed: Optional[str],
    fallback_vulnerable: Optional[str],
    repo_url: Optional[str] = None,
) -> tuple[Optional[str], Optional[str]]:
    fixed_ref = fallback_fixed

    for item in osv_payload.get("references", []):
        url = item.get("url", "")
        if "github.com" in url and "/commit/" in url:
            fixed_ref = fixed_ref or url.rstrip("/").split("/")[-1].replace(".patch", "")
            break

    for affected in osv_payload.get("affected", []):
        for item in affected.get("ranges", []):
            if item.get("type") != "GIT":
                continue
            for event in item.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    fixed_ref = fixed_ref or fixed

    vulnerable_ref = fetch_github_parent_ref(repo_url, fixed_ref) or fallback_vulnerable
    return vulnerable_ref, fixed_ref


def extract_summary_candidate(page: FetchedPage) -> str:
    text = page.cleaned_text.strip()
    if not text:
        return ""

    section_markers = ("Description", "Impact", "Summary", "Details")
    lines = [line.strip() for line in text.splitlines()]
    for index, line in enumerate(lines):
        if line not in section_markers:
            continue
        collected: list[str] = []
        for candidate in lines[index + 1 :]:
            if not candidate:
                if collected:
                    break
                continue
            if candidate in section_markers or len(candidate) <= 2:
                if collected:
                    break
                continue
            collected.append(candidate)
            if sum(len(item) for item in collected) >= 700:
                break
        if collected:
            return " ".join(collected)[:1000]

    paragraphs = [paragraph.strip() for paragraph in text.split("\n\n") if paragraph.strip()]
    for paragraph in paragraphs:
        lowered = paragraph.lower()
        if any(noise in lowered for noise in ("navigation menu", "toggle navigation", "search or jump to")):
            continue
        if len(paragraph) >= 80:
            return paragraph[:1000]

    first_paragraph = paragraphs[0] if paragraphs else ""
    return first_paragraph[:1000] if first_paragraph else ""


def page_summary_score(page: FetchedPage) -> int:
    lowered_url = page.url.lower()
    lowered_text = page.cleaned_text.lower()
    score = 0

    if "nvd.nist.gov/vuln/detail/" in lowered_url:
        score += 50
    if "/security/advisories/" in lowered_url or "ghsa-" in lowered_url:
        score += 45
    if "cveproject" in lowered_url or "cvelist" in lowered_url or "osv.dev" in lowered_url:
        score += 35
    if "/commit/" in lowered_url:
        score -= 20
    if ".diff" in lowered_url or ".patch" in lowered_url:
        score -= 10
    if "description" in lowered_text:
        score += 20
    if "impact" in lowered_text:
        score += 10
    if "navigation menu" in lowered_text:
        score -= 15

    candidate = extract_summary_candidate(page)
    if len(candidate) >= 120:
        score += 10
    return score


def heuristic_summary_from_pages(fetched_pages: List[FetchedPage]) -> str:
    ranked_pages = sorted(
        (page for page in fetched_pages if page.cleaned_text.strip()),
        key=page_summary_score,
        reverse=True,
    )
    for page in ranked_pages:
        candidate = extract_summary_candidate(page)
        if candidate:
            return candidate
    return ""


def infer_vulnerability_type(text: str) -> str:
    lowered = text.lower()
    mapping = [
        ("heap-buffer-overflow", "heap-buffer-overflow"),
        ("stack-buffer-overflow", "stack-buffer-overflow"),
        ("use-after-free", "use-after-free"),
        ("null pointer", "null-pointer-dereference"),
        ("out-of-bounds", "out-of-bounds-access"),
        ("denial of service", "denial-of-service"),
        ("privilege escalation", "privilege-escalation"),
        ("authentication bypass", "authentication-bypass"),
        ("authorization bypass", "authorization-bypass"),
        ("business logic", "business-logic-error"),
        ("protocol rule", "business-logic-error"),
        ("improper validation", "improper-input-validation"),
        ("validation", "improper-input-validation"),
        ("not checked", "improper-input-validation"),
    ]
    for needle, label in mapping:
        if needle in lowered:
            return label
    return ""


def default_error_patterns(vulnerability_type: str) -> List[str]:
    if vulnerability_type == "heap-buffer-overflow":
        return ["AddressSanitizer: heap-buffer-overflow"]
    if vulnerability_type == "stack-buffer-overflow":
        return ["AddressSanitizer: stack-buffer-overflow"]
    if vulnerability_type == "use-after-free":
        return ["AddressSanitizer: heap-use-after-free"]
    return []


def extract_stack_keywords(patch_summaries: List[PatchSummary]) -> List[str]:
    keywords = []
    for summary in patch_summaries:
        keywords.extend(summary.changed_functions)
    return dedupe_preserve_order(keyword for keyword in keywords if keyword)[:10]


def build_reproduction_hints(task: TaskModel, fetched_pages: List[FetchedPage], patch_summaries: List[PatchSummary]) -> List[str]:
    hints: list[str] = []
    if task.repo_url:
        hints.append("Clone the target repository and inspect the vulnerable and fixed revisions.")
    if task.vulnerable_ref:
        hints.append(f"Start from the vulnerable revision: {task.vulnerable_ref}.")
    if task.fixed_ref:
        hints.append(f"Compare with the fixed revision: {task.fixed_ref}.")
    if patch_summaries:
        hints.append("Review the patch to identify the modified files and triggering path.")
    if any(page.cleaned_text for page in fetched_pages):
        hints.append("Use the cleaned advisory or discussion pages to recover trigger conditions and expected error signatures.")
    return dedupe_preserve_order(hints)


def parse_llm_json_payload(content) -> Optional[dict]:
    """Parse a JSON object from an LLM response payload."""

    if isinstance(content, list):
        text_parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str):
                    text_parts.append(text)
            elif isinstance(item, str):
                text_parts.append(item)
        content = "\n".join(text_parts)

    if not isinstance(content, str):
        return None

    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)

    try:
        return json.loads(stripped)
    except Exception:
        match = re.search(r"\{.*\}", stripped, re.DOTALL)
        if not match:
            return None
        try:
            return json.loads(match.group(0))
        except Exception:
            return None
