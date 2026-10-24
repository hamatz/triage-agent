import json
from pathlib import Path
from typing import List, Optional
from google import genai
from google.genai import types

from triage_agent.config import get_gemini_api_key, get_model_name
from triage_agent.schemas import ComponentInfo, ReconPlan
from triage_agent.tools.osv import query_osv_batch
from triage_agent.tools.sbom import load_sbom_summary

PROMPT_PATH = Path(__file__).resolve().parent.parent.parent.parent / "prompts" / "recon_planner.md"


def run_recon_planner(
    sbom_path: str,
    custom_system_context: Optional[str] = None,
    client: Optional[genai.Client] = None,
) -> ReconPlan:
    """Execute the Recon Planner agent.
    
    1. Loads components from the SBOM file.
    2. Runs a batch query against OSV.dev to find known CVE/GHSA alerts.
    3. Prompts the LLM (Recon Planner) to analyze the attack surface and output a structured ReconPlan.
    """
    # 1. Load SBOM components
    components: List[ComponentInfo] = load_sbom_summary(sbom_path)
    if not components:
        return ReconPlan(
            summary="No components found in SBOM.",
            total_components_scanned=0,
            known_osv_hits_count=0,
            targets=[],
        )

    # 2. Query OSV.dev in batch
    osv_results = query_osv_batch(components)

    # 3. Prepare payload for Gemini
    if client is None:
        api_key = get_gemini_api_key()
        client = genai.Client(api_key=api_key) if api_key else genai.Client()

    model_name = get_model_name("planner")

    # Load system prompt
    system_instruction = PROMPT_PATH.read_text(encoding="utf-8")
    if custom_system_context:
        system_instruction += f"\n\n### 自社システムの追加コンテキスト:\n{custom_system_context}"

    # Prepare input prompt with SBOM summary and OSV hits
    sbom_summary_text = json.dumps([c.model_dump() for c in components], indent=2, ensure_ascii=False)
    osv_summary_text = json.dumps(osv_results, indent=2, ensure_ascii=False)

    user_content = f"""以下は自社システムから抽出したSBOMコンポーネント一覧と、OSV.devの一括照会結果です。

【SBOMコンポーネント一覧 (計 {len(components)} 件)】:
{sbom_summary_text}

【OSV.dev 既知脆弱性照会結果 (ヒット件数: {len(osv_results)} コンポーネント)】:
{osv_summary_text}

上記を分析し、外部露出・RCE傾向・事前予告の可能性を踏まえた動的調査計画（ReconPlan）を策定してください。
"""

    response = client.models.generate_content(
        model=model_name,
        contents=user_content,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=ReconPlan,
            temperature=0.2,
        ),
    )

    if response.text:
        return ReconPlan.model_validate_json(response.text)
    raise RuntimeError("Recon Planner failed to produce a valid structured response.")
