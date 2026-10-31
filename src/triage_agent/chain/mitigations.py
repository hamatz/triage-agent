"""Linux Kernel LPE Mitigation Evaluation Engine (v0.4.0 / ADR-019).

Evaluates whether kernel mitigations (such as Fragnesia's 3-module modprobe disabling)
are genuinely active on the host, while detecting operational side-effects (e.g. IPsec breakage).
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import tomllib

from triage_agent.chain.models import NodeTelemetry

_CONFIG_PATH = Path(__file__).resolve().parent / "kernel_mitigations.toml"


def load_kernel_mitigations(toml_path: Optional[str] = None) -> Dict[str, Any]:
    """Load verified kernel mitigation registry from TOML."""
    p = Path(toml_path) if toml_path else _CONFIG_PATH
    if not p.exists():
        return {}
    try:
        with open(p, "rb") as f:
            data = tomllib.load(f)
            return data.get("mitigations", {})
    except Exception:
        return {}


def evaluate_kernel_mitigation(
    cve_id: str,
    telemetry: Optional[NodeTelemetry] = None,
    mitigations_registry: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Evaluate whether an LPE mitigation is fully verified, blocked by side-effects, or unmitigated.
    
    Returns:
        Dict with keys:
            - is_mitigated: bool
            - status: str ('MITIGATED', 'UNMITIGATED', 'BLOCKED_BY_SIDE_EFFECT', 'BUILTIN_CANNOT_DISABLE', 'NO_MITIGATION_DATA')
            - reasoning: str
            - side_effect_warning: Optional[str]
            - source_url: Optional[str]
    """
    registry = mitigations_registry if mitigations_registry is not None else load_kernel_mitigations()
    entry = registry.get(cve_id)

    if not entry:
        return {
            "is_mitigated": False,
            "status": "NO_MITIGATION_DATA",
            "reasoning": f"{cve_id} の緩和策データ未登録（安全側に倒し未緩和として評価）",
            "side_effect_warning": None,
            "source_url": None,
        }

    source_url = entry.get("source_url")
    side_effect = entry.get("side_effect_warning")
    required_mods = entry.get("required_modules", [])
    conflict_services = [s.lower() for s in entry.get("conflict_services", [])]

    if telemetry is None:
        return {
            "is_mitigated": False,
            "status": "UNMITIGATED",
            "reasoning": "実機テレメトリ未取得（実機未確認のため安全側に倒し未緩和として評価）",
            "side_effect_warning": side_effect,
            "source_url": source_url,
        }

    # 1. Side-effect conflict check: Is an affected service (e.g. IPsec, strongswan) or xfrm active?
    active_srvs = [s.lower() for s in telemetry.active_services]
    active_conflicts = [c for c in conflict_services if any(c in a for a in active_srvs)]
    if active_conflicts or telemetry.xfrm_active:
        conflict_desc = ', '.join(active_conflicts) if active_conflicts else "IPsec xfrm (デーモンレス暗号化通信)"
        return {
            "is_mitigated": False,
            "status": "BLOCKED_BY_SIDE_EFFECT",
            "reasoning": (
                f"【副作用による緩和不可】当該ノード上で競合通信・サービス（{conflict_desc}）を検知しました。"
                f"モジュール無効化は通信切断等の重大な副作用を引き起こすため適用不可（未緩和・カーネルパッチ適用必須）として評価します。"
            ),
            "side_effect_warning": side_effect,
            "source_url": source_url,
        }

    # 2. Built-in module check: Is any required module built directly into the kernel?
    builtins = [b.lower() for b in telemetry.builtin_modules]
    builtin_hits = [m for m in required_mods if m.lower() in builtins]
    if builtin_hits:
        return {
            "is_mitigated": False,
            "status": "BUILTIN_CANNOT_DISABLE",
            "reasoning": (
                f"【組み込みモジュール検出】対象モジュール（{', '.join(builtin_hits)}）がカーネル本体に直接組み込まれています"
                f"（modules.builtin）。modprobe では無効化不能のため未緩和（カーネルアップデート必須）と判定します。"
            ),
            "side_effect_warning": side_effect,
            "source_url": source_url,
        }

    # 3. Modprobe directive check: Are ALL required modules disabled via install /bin/false?
    disabled_mods = [d.lower() for d in telemetry.modprobe_disabled_modules]
    missing_disabled = [m for m in required_mods if m.lower() not in disabled_mods]
    if missing_disabled:
        return {
            "is_mitigated": False,
            "status": "UNMITIGATED",
            "reasoning": (
                f"【緩和策未完了】必要な全モジュール（{', '.join(required_mods)}）のうち、"
                f"{', '.join(missing_disabled)} の無効化（install /bin/false）が確認できませんでした（未緩和）。"
            ),
            "side_effect_warning": side_effect,
            "source_url": source_url,
        }

    # 4. Currently loaded module check: Are any required modules currently loaded in kernel memory?
    # Even if install /bin/false is configured, previously loaded modules remain active until unloaded or rebooted.
    loaded_mods = [l.lower() for l in telemetry.loaded_modules]
    still_loaded = [m for m in required_mods if m.lower() in loaded_mods]
    if still_loaded:
        return {
            "is_mitigated": False,
            "status": "UNMITIGATED",
            "reasoning": (
                f"【緩和策未反映】modprobe の無効化設定は存在しますが、対象モジュール（{', '.join(still_loaded)}）が"
                f"現在カーネルメモリ内に読み込まれています（/proc/modules）。アンロード（modprobe -r / rmmod）またはノード再起動が完了するまで未緩和です。"
            ),
            "side_effect_warning": side_effect,
            "source_url": source_url,
        }

    # All checks passed: Fully mitigated
    return {
        "is_mitigated": True,
        "status": "MITIGATED",
        "reasoning": f"全対象モジュール（{', '.join(required_mods)}）の無効化（install /bin/false）および競合サービス非稼働を確認済み（緩和確認済み）。",
        "side_effect_warning": side_effect,
        "source_url": source_url,
    }
