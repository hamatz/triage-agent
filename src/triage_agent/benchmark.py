"""Ground-Truth Benchmark Suite Runner for Verifier and Advisory Feeds (ADR-019 / Pillar 4).

Executes all positive, negative, hard edge cases, and feed pre-announcement fixtures
from benchmark/manifest.json, evaluates accuracy, and outputs quantifiable metrics
for PoC trial evaluation and governance reporting.
"""

from datetime import date, datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.tools.advisory_catalog import fetch_advisory_feed, load_advisory_catalog
from triage_agent.verifier.engine import verify_codebase


def find_benchmark_dir() -> Path:
    """Locate benchmark directory across local development, scratch, and installed modes."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "benchmark",
        Path.cwd() / "benchmark",
        Path(__file__).resolve().parent / "benchmark",
    ]
    for c in candidates:
        if c.exists() and (c / "manifest.json").exists():
            return c
    raise FileNotFoundError(
        "評価セット 'benchmark/manifest.json' が見つかりませんでした。\n"
        "※ 評価セット（benchmark/）は PyPI 配布パッケージには同梱されず、GitHub リポジトリに配置されています。\n"
        "リポジトリを clone したルートディレクトリで実行してください。"
    )


def _build_checkpoint_for_case(case: Dict[str, Any]) -> CheckPointItem:
    """Construct a precise CheckPointItem from benchmark case definition."""
    cp_yes_no = case.get("check_point_yes_no")
    cp_method = case.get("verification_method")

    if not cp_yes_no:
        cfg = case.get("config_check")
        if case.get("test_type") == "code":
            kw = case.get("search_keywords", ["verify"])[0]
            cp_yes_no = f"{kw} 呼び出しで algorithms が指定されているか"
            cp_method = f"`jwt.{kw}` の呼び出し箇所で第三引数 options.algorithms が指定されているか確認"
        elif cfg == "tomcat_ajp":
            cp_yes_no = "AJP コネクタを有効にしているか"
            cp_method = "`server.xml` で `<Connector protocol=\"AJP/1.3\"` が有効か確認"
        elif cfg == "nginx_http2":
            cp_yes_no = "HTTP/2 を有効にしているか"
            cp_method = "`nginx.conf` で `http2 on;` または `listen ... http2;` を確認"
        elif cfg == "php_upload_progress":
            cp_yes_no = "session.upload_progress.enabled が有効か"
            cp_method = "`php.ini` の `session.upload_progress.enabled` を確認"
        elif case["id"] == "case_d_tomcat_http2_isolation":
            cp_yes_no = "HTTP/2 を有効にしているか"
            cp_method = "`server.xml` で `http2` UpgradeProtocol を確認"
        else:
            cp_yes_no = "脆弱な設定が存在するか"
            cp_method = "`server.xml` や `php.ini` などの設定ファイルを確認"

    return CheckPointItem(
        target_or_cve=case["target_cve"],
        cvss="9.0",
        content_summary=case["name"],
        affected_versions="all",
        check_point_yes_no=cp_yes_no,
        verification_method=cp_method,
        config_check=case.get("config_check"),
    )


def run_benchmark_suite(benchmark_dir: Optional[Path] = None, output_file: Optional[Path] = None) -> Dict[str, Any]:
    """Execute all benchmark test cases and return structured results."""
    b_dir = benchmark_dir or find_benchmark_dir()
    manifest_path = b_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    ref_date = date(2026, 10, 29)
    results: List[Dict[str, Any]] = []

    pos_total = 0
    pos_detected = 0
    neg_total = 0
    neg_safe = 0
    unverified_count = 0

    # 1. Standard Positive Cases
    for case in manifest.get("cases", []):
        pos_total += 1
        target_dir = b_dir / case["target_dir"]
        report = TriageReport(
            report_title=f"Benchmark: {case['name']}",
            scan_target=case["id"],
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name=case.get("component_name", "target"),
                    component_name=case.get("component_name", "target"),
                    announcement_date="2026-10-25",
                    conclusion=case.get("description", ""),
                    fixed_versions="fixed",
                    severity_note="High",
                    check_points=[_build_checkpoint_for_case(case)],
                )
            ],
        )
        audit_res = verify_codebase(report, code_dir_path=str(target_dir))
        cp_res = audit_res.notice_results[0].results[0]
        is_yes = "YES" in cp_res.status.upper()
        passed = (case["expected"] == "YES" and is_yes) or (case["expected"] != "YES" and not is_yes)
        if is_yes:
            pos_detected += 1

        results.append({
            "id": case["id"],
            "category": "positive",
            "name": case["name"],
            "expected": case["expected"],
            "actual_status": cp_res.status,
            "passed": passed,
            "reasoning": cp_res.reasoning,
        })

    # 2. Negative Cases
    for case in manifest.get("negative_cases", []):
        neg_total += 1
        target_dir = b_dir / case["target_dir"]
        report = TriageReport(
            report_title=f"Benchmark Negative: {case['name']}",
            scan_target=case["id"],
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name=case.get("component_name", "target"),
                    component_name=case.get("component_name", "target"),
                    announcement_date="2026-10-25",
                    conclusion=case.get("description", ""),
                    fixed_versions="fixed",
                    severity_note="High",
                    check_points=[_build_checkpoint_for_case(case)],
                )
            ],
        )
        audit_res = verify_codebase(report, code_dir_path=str(target_dir))
        cp_res = audit_res.notice_results[0].results[0]
        is_yes = "YES" in cp_res.status.upper()
        passed = not is_yes  # Negative cases must NOT report YES
        if passed:
            neg_safe += 1

        results.append({
            "id": case["id"],
            "category": "negative",
            "name": case["name"],
            "expected": case["expected"],
            "actual_status": cp_res.status,
            "passed": passed,
            "reasoning": cp_res.reasoning,
        })

    # 3. Hard Edge Cases (Pillar 2 Discoveries)
    for case in manifest.get("hard_cases", []):
        target_dir = b_dir / case["target_dir"]
        expected = case["expected"]
        if expected == "YES":
            pos_total += 1
        else:
            neg_total += 1

        report = TriageReport(
            report_title=f"Benchmark Hard: {case['name']}",
            scan_target=case["id"],
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name=case.get("component_name", "target"),
                    component_name=case.get("component_name", "target"),
                    announcement_date="2026-10-25",
                    conclusion=case.get("description", ""),
                    fixed_versions="fixed",
                    severity_note="High",
                    check_points=[_build_checkpoint_for_case(case)],
                )
            ],
        )
        audit_res = verify_codebase(report, code_dir_path=str(target_dir))
        cp_res = audit_res.notice_results[0].results[0]

        is_yes = "YES" in cp_res.status.upper()
        is_unverified = "要確認" in cp_res.status or "外部設定要確認" in cp_res.status or "要手動確認" in cp_res.status

        if expected == "YES":
            passed = is_yes
            if is_yes:
                pos_detected += 1
        elif expected == "UNVERIFIED":
            passed = is_unverified and not is_yes
            if is_unverified:
                unverified_count += 1
            if not is_yes:
                neg_safe += 1
        else:
            passed = not is_yes
            if not is_yes:
                neg_safe += 1

        results.append({
            "id": case["id"],
            "category": "hard",
            "name": case["name"],
            "expected": expected,
            "actual_status": cp_res.status,
            "passed": passed,
            "reasoning": cp_res.reasoning,
        })

    # 4. Feed Pre-announcement Cases (Driven by live advisory catalog ADR-020)
    catalog = load_advisory_catalog()
    catalog_by_id = {s["id"]: s for s in catalog if "id" in s}

    for case in manifest.get("feed_cases", []):
        feed_path = b_dir / case["feed_file"]
        xml_content = feed_path.read_text(encoding="utf-8")
        raw_src = catalog_by_id.get(case["source_id"])
        if raw_src:
            src = raw_src.copy()
        else:
            src = {
                "id": case["source_id"],
                "name": "Advisory Feed",
                "keywords": ["security release", "security releases", "pre-announcement"],
            }
        # Ensure feed_url is present for fetch_advisory_feed dispatcher
        if not src.get("feed_url"):
            src["feed_url"] = src.get("url") or "https://example.com/feed.xml"

        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = xml_content.encode("utf-8")
            feed_res, feed_err = fetch_advisory_feed(src, reference_date=ref_date)

        expected = case["expected"]
        if expected == "YES":
            pos_total += 1
            passed = feed_res is not None
            if passed:
                pos_detected += 1
                if "expected_date" in case and feed_res.get("expected_date") != case["expected_date"]:
                    passed = False
        else:
            neg_total += 1
            passed = feed_res is None
            if passed:
                neg_safe += 1

        results.append({
            "id": case["id"],
            "category": "feed",
            "name": case["name"],
            "expected": expected,
            "actual_status": "FEED_DETECTED" if feed_res else "FEED_NONE",
            "passed": passed,
            "reasoning": f"feed_res: {feed_res}, err: {feed_err}",
        })

    # 5. Exploit Chain & Kernel Exposure Cases (v0.4.0 / ADR-019)
    from triage_agent.chain.engine import run_exploit_chain_audit
    from triage_agent.chain.feeds import ThreatFeedResult
    from triage_agent.chain.models import (
        DistroAffectedRange,
        EnvironmentDefinition,
        ExposureType,
        KernelVulnerabilityEntry,
        NodePoolDefinition,
        NodeTelemetry,
        WorkloadDefinition,
    )

    # Mocked threat feed results for benchmark suite (Upholds: feeds injected, no hardcoded engine lists)
    mock_feed_results = {
        "CVE-2026-109618": ThreatFeedResult(
            cve_id="CVE-2026-109618",
            in_cisa_kev=True,
            epss_score=0.42,
            verified=True,
        ),
        "CVE-2026-46300": ThreatFeedResult(
            cve_id="CVE-2026-46300",
            in_cisa_kev=True,
            epss_score=0.42,
            verified=True,
        ),
    }

    for case in manifest.get("chain_cases", []):
        pos_total += 1
        raw_exp = case["workload_exposure"].lower()
        if raw_exp == "untrusted_code":
            exp_type = ExposureType.UNTRUSTED_CODE
        elif raw_exp == "internet_facing":
            exp_type = ExposureType.INTERNET_FACING
        else:
            exp_type = ExposureType.INTERNAL_ONLY

        sbom_path_val = case.get("sbom_path")
        if sbom_path_val:
            p_cand = b_dir / sbom_path_val
            if p_cand.exists():
                sbom_path_val = str(p_cand.resolve())

        bench_triage_report = None
        if "triage_notices" in case:
            notices = []
            for n_data in case["triage_notices"]:
                cps = [
                    CheckPointItem(
                        target_or_cve=cp.get("target_or_cve", ""),
                        cvss=str(cp.get("cvss", "")),
                        content_summary=cp.get("content_summary", ""),
                        affected_versions=cp.get("affected_versions", ""),
                        check_point_yes_no=cp.get("check_point_yes_no", ""),
                        verification_method=cp.get("verification_method", ""),
                    )
                    for cp in n_data.get("check_points", [])
                ]
                notices.append(
                    TriageNotice(
                        product_name=n_data.get("product_name", ""),
                        component_name=n_data.get("component_name", ""),
                        announcement_date=n_data.get("announcement_date", "2026-10-24"),
                        conclusion=n_data.get("conclusion", ""),
                        fixed_versions=n_data.get("fixed_versions", ""),
                        severity_note=n_data.get("severity_note", ""),
                        check_points=cps,
                    )
                )
            bench_triage_report = TriageReport(
                report_title="Benchmark Triage Report",
                scan_target=sbom_path_val or "benchmark_sbom.json",
                total_dependencies=len(notices),
                notices=notices,
            )

        env = EnvironmentDefinition(
            environment_name="benchmark_env",
            node_pools=[
                NodePoolDefinition(
                    pool_id="bench_pool",
                    os_distribution="ubuntu",
                    os_release="24.04",
                    kernel_package_name=case.get("kernel_package_name", "linux-image-generic"),
                    kernel_flavor=case.get("kernel_flavor"),
                    kernel_package_version=case["kernel_version"],
                )
            ],
            workloads=[
                WorkloadDefinition(
                    name="bench_workload",
                    exposure=exp_type,
                    node_pool="bench_pool",
                    components=case.get("components", case["entry_cves"]),
                    sbom_path=sbom_path_val,
                )
            ],
        )
        telemetry = NodeTelemetry(
            pool_id="bench_pool",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name=case.get("kernel_package_name", "linux-image-generic"),
            kernel_flavor=case.get("kernel_flavor"),
            kernel_package_version=case["kernel_version"],
            loaded_modules=case.get("loaded_modules", []),
            modprobe_disabled_modules=case.get("disabled_modules", []),
            active_services=case.get("active_services", []),
        )
        k_entry = KernelVulnerabilityEntry(
            cve_id="CVE-2026-46300",
            name="Fragnesia IPsec LPE",
            source_url="https://ubuntu.com/security/notices/USN-7000-1",
            retrieved_at="2026-10-31",
            epss_score=0.42,
            cisa_kev=True,
            poc_available=True,
            distro_affected_ranges={
                "ubuntu": DistroAffectedRange(
                    package="linux",
                    fixed_version=case["fixed_version"],
                )
            },
        )

        chain_items = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[k_entry],
            telemetries={"bench_pool": telemetry},
            evaluation_date="2026-10-31",
            feed_results=mock_feed_results,
            triage_report=bench_triage_report,
        )
        item = chain_items[0]
        actual_level = item.chain_level.value
        expected_level = case["expected_level"]
        level_match = actual_level == expected_level
        deadline_match = case.get("expected_deadline", "") in item.action_deadline
        passed = level_match and deadline_match

        if passed:
            pos_detected += 1

        results.append({
            "id": case["id"],
            "category": "chain",
            "name": case["name"],
            "expected": expected_level,
            "actual_status": f"{actual_level} ({item.action_deadline})",
            "passed": passed,
            "reasoning": f"Level match: {level_match}, Deadline match: {deadline_match}, Mitigation: {item.mitigation_status}",
        })

    # Calculate overall metrics
    total_cases = len(results)
    passed_cases = sum(1 for r in results if r["passed"])
    failed_cases = total_cases - passed_cases
    accuracy_rate = (passed_cases / total_cases * 100.0) if total_cases > 0 else 0.0

    pos_missed = pos_total - pos_detected
    neg_false_positives = neg_total - neg_safe

    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "manifest_version": manifest.get("version", "1.0.0"),
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "accuracy_rate": round(accuracy_rate, 2),
        "metrics": {
            "positive_total": pos_total,
            "positive_detected": pos_detected,
            "positive_missed": pos_missed,
            "negative_total": neg_total,
            "negative_safe": neg_safe,
            "negative_false_positives": neg_false_positives,
            "unverified_count": unverified_count,
        },
        "headline": f"陽性 {pos_total}件中 {pos_detected}件検出（見逃し {pos_missed}）／陰性 {neg_total}件中 誤検知 {neg_false_positives}／要確認 {unverified_count}件",
        "results": results,
    }

    # Save to triage-output/benchmark_results.json
    out_p = output_file or (Path("triage-output") / "benchmark_results.json")
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    return summary


def main():
    """CLI entrypoint for python -m triage_agent.benchmark."""
    try:
        summary = run_benchmark_suite()
        m = summary["metrics"]
        print("=" * 70)
        print("triage-agent Verifier & Feed Benchmark Suite (ADR-019 / Pillar 4)")
        print("=" * 70)
        print(summary["headline"])
        print(f"総合正解率: {summary['accuracy_rate']}% ({summary['passed_cases']}/{summary['total_cases']} ケース合格)")
        print(f"詳細結果保存先: triage-output/benchmark_results.json")
        print("=" * 70)

        if summary["failed_cases"] > 0:
            print("\n❌ 失敗したテストケース:")
            for r in summary["results"]:
                if not r["passed"]:
                    print(f"  - [{r['id']}] {r['name']} (期待: {r['expected']}, 実際: {r['actual_status']})")
            sys.exit(1)
        else:
            print("✅ 全ベンチマークケース合格（リグレッションなし）")
            sys.exit(0)
    except Exception as e:
        print(f"❌ ベンチマーク実行エラー: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
