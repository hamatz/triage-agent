"""Specialized configuration file scanner (XML, INI, Nginx/Apache Conf, Properties).

Implements deterministic inspection for middleware and infrastructure configurations (ADR-019),
ensuring comments are completely stripped, multiple config files are fully scanned,
PHP conf.d overrides and pool configurations are evaluated hierarchically,
and unverified external settings are never falsely declared safe.
"""

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple


@dataclass
class ConfigVerificationResult:
    is_applicable: bool
    status: str  # "YES (設定有効:...)" | "NO (設定無効化確認)" | "外部設定要確認 (...)"
    evidence_file: Optional[str] = None
    line_number: Optional[int] = None
    detail: str = ""


def is_config_inspection(
    verification_method: str,
    check_point_yes_no: str,
    config_check: Optional[str] = None
) -> bool:
    """Determine whether this check point targets specialized middleware configuration files."""
    if config_check:
        return config_check in ("tomcat_ajp", "nginx_http2", "php_upload_progress")

    combined = f"{check_point_yes_no} {verification_method}".lower()

    # Strict composite matching to prevent false positives across products
    if ("tomcat" in combined or "server.xml" in combined) and any(k in combined for k in ["ajp", "ghostcat", "8009"]):
        return True
    if ("php" in combined or "php.ini" in combined) and any(k in combined for k in ["upload_progress", "session.upload_progress"]):
        return True
    if ("nginx" in combined or "nginx.conf" in combined) and "http2" in combined:
        if not any(other in combined for other in ["tomcat", "node", "brotli", "apache"]):
            return True

    return False


def scan_tomcat_server_xml(code_dir: Path, target_cve: Optional[str] = None) -> Optional[ConfigVerificationResult]:
    """Inspect all Tomcat server.xml files for AJP or sensitive connector configurations.
    
    Scans every server.xml file:
    - If ANY file contains an unprotected AJP connector -> YES (Vulnerable)
    - If ANY file cannot be parsed as valid XML (e.g. &nbsp; or syntax error) -> 外部設定要確認
    - If ALL files explicitly have no AJP connector or are fully protected -> NO (Safe)
    """
    server_xml_files: List[Path] = []
    for root, _, files in os.walk(code_dir):
        for fname in sorted(files):
            if fname.lower() == "server.xml":
                server_xml_files.append(Path(root) / fname)

    if not server_xml_files:
        return None

    yes_results: List[ConfigVerificationResult] = []
    parse_error_results: List[ConfigVerificationResult] = []
    no_results: List[ConfigVerificationResult] = []

    for fpath in server_xml_files:
        rel_path = str(fpath.relative_to(code_dir))
        try:
            tree = ET.parse(fpath)
            root_elem = tree.getroot()

            # Check for AJP connectors (Ghostcat CVE-2020-1938)
            ajp_connectors = []
            for conn in root_elem.iter("Connector"):
                proto = conn.get("protocol", "")
                if "AJP" in proto.upper() or "ajp" in proto.lower():
                    ajp_connectors.append(conn)

            if not ajp_connectors:
                no_results.append(
                    ConfigVerificationResult(
                        is_applicable=True,
                        status="NO (設定無効化確認)",
                        evidence_file=rel_path,
                        detail=f"{rel_path}: AJP/1.3 コネクタは未定義またはコメントアウトされています（非該当）。"
                    )
                )
                continue

            # AJP connector found. Check if protected with secret / secretRequired / requiredSecret
            vulnerable_conn = None
            for conn in ajp_connectors:
                port = conn.get("port", "8009")
                secret = conn.get("secret")
                secret_required = conn.get("secretRequired", "").lower()
                required_secret = conn.get("requiredSecret")  # Legacy Tomcat 9.0.30 and older attribute

                # Protected condition:
                # 1. secretRequired="true" and secret is configured
                # 2. Legacy requiredSecret is configured
                # 3. secret is configured and secretRequired is not explicitly "false"
                is_protected = (
                    (secret_required == "true" and secret) or
                    (required_secret is not None and required_secret.strip() != "") or
                    (secret is not None and secret.strip() != "" and secret_required != "false")
                )

                if is_protected:
                    continue
                else:
                    vulnerable_conn = (conn, port)
                    break

            if vulnerable_conn:
                conn, port = vulnerable_conn
                # Find line number in raw file (handling multiline <Connector ... > blocks)
                raw_lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                line_no = 1
                connector_start = None
                for idx, line in enumerate(raw_lines, 1):
                    if "<Connector" in line:
                        connector_start = idx
                    if "AJP" in line.upper() and connector_start is not None:
                        line_no = connector_start
                        break
                    if "/>" in line or "</Connector>" in line:
                        if connector_start is not None and "AJP" in line.upper():
                            line_no = connector_start
                            break
                        connector_start = None

                yes_results.append(
                    ConfigVerificationResult(
                        is_applicable=True,
                        status="YES (設定有効: AJPコネクタ有効かつ認証未保護)",
                        evidence_file=rel_path,
                        line_number=line_no,
                        detail=(
                            f"{rel_path}:{line_no} AJP/1.3 コネクタ（port={port}）が有効化されており、"
                            f"secret/secretRequired による保護が未設定です（Ghostcat 影響対象）。"
                        )
                    )
                )
            else:
                no_results.append(
                    ConfigVerificationResult(
                        is_applicable=True,
                        status="NO (設定無効化確認)",
                        evidence_file=rel_path,
                        detail=f"{rel_path}: AJP コネクタに secretRequired / secret / requiredSecret が設定されており保護されています。"
                    )
                )

        except Exception as e:
            # XML parsing failed (syntax error, undeclared entity like &nbsp;, or truncated)
            # Do NOT silently drop! Report as unverified so humans check.
            parse_error_results.append(
                ConfigVerificationResult(
                    is_applicable=True,
                    status="外部設定要確認 (構文解析エラー: XML形式不正)",
                    evidence_file=rel_path,
                    detail=f"{rel_path}: XMLの構文解析に失敗しました ({type(e).__name__}: {e})。実ファイルを手動確認してください。"
                )
            )

    # Aggregation logic:
    # 1. If any file has a vulnerable active configuration -> YES
    if yes_results:
        return yes_results[0]
    # 2. If any file failed to parse -> Unverified
    if parse_error_results:
        return parse_error_results[0]
    # 3. Only if ALL files are safely verified -> NO
    if no_results:
        return no_results[0]

    return None


def scan_php_ini(code_dir: Path, target_cve: Optional[str] = None) -> Optional[ConfigVerificationResult]:
    """Inspect PHP configuration files for session.upload_progress or unsafe PHP runtime directives.
    
    Correctly evaluates hierarchical overrides:
    1. Base php.ini is read first.
    2. conf.d/*.ini are loaded in alphabetical order, overriding earlier directives (late-binding/last-wins).
    3. Distribution templates (php.ini-production, php.ini-development) are skipped.
    4. If php.ini or conf.d sets Off, but potentially overriding configs exist (php-fpm pool configs, .user.ini, .htaccess),
       returns 外部設定要確認 unless verified.
    """
    base_ini_files: List[Path] = []
    override_ini_files: List[Path] = []
    pool_and_htaccess_files: List[Path] = []

    for root, _, files in os.walk(code_dir):
        rel_dir = str(Path(root).relative_to(code_dir)).lower()
        for fname in sorted(files):
            fl = fname.lower()
            # Explicitly exclude distribution templates
            if fl in ("php.ini-production", "php.ini-development", "php.ini-dist", "php.ini-recommended"):
                continue

            fpath = Path(root) / fname
            if fl == "php.ini":
                base_ini_files.append(fpath)
            elif fl.endswith(".ini") and ("conf.d" in rel_dir or "php" in rel_dir or "etc" in rel_dir):
                override_ini_files.append(fpath)
            elif fl in (".user.ini", ".htaccess") or (fl.endswith(".conf") and ("fpm" in rel_dir or "pool" in rel_dir)):
                pool_and_htaccess_files.append(fpath)

    # If no PHP config files exist at all
    if not base_ini_files and not override_ini_files and not pool_and_htaccess_files:
        return None

    # Sort files in execution/load order: php.ini first, then conf.d/*.ini alphabetically
    ordered_files = list(base_ini_files) + sorted(override_ini_files, key=lambda p: p.name.lower())

    # Current evaluation state
    latest_state: Optional[bool] = None  # True: On, False: Off, None: unset
    latest_evidence_file: Optional[str] = None
    latest_line_no: Optional[int] = None
    files_evaluated: List[str] = []

    for fpath in ordered_files:
        rel_path = str(fpath.relative_to(code_dir))
        files_evaluated.append(rel_path)
        try:
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, raw_line in enumerate(lines, 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith(";") or stripped.startswith("#"):
                    continue

                if "=" in stripped:
                    key, val = [p.strip() for p in stripped.split("=", 1)]
                    if key.lower() == "session.upload_progress.enabled":
                        val_clean = val.lower().split(";")[0].split("#")[0].strip()
                        is_on = val_clean in ("on", "1", "yes", "true")
                        latest_state = is_on
                        latest_evidence_file = rel_path
                        latest_line_no = idx
        except Exception:
            continue

    # Also check php-fpm pool configs or .htaccess / .user.ini for overrides
    # If ANY file enables upload_progress (e.g. php_admin_value or php_flag), it's immediately YES.
    fpm_explicit_off = False
    fpm_off_evidence_file = None
    fpm_off_line_no = None

    for fpath in pool_and_htaccess_files:
        rel_path = str(fpath.relative_to(code_dir))
        try:
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            for idx, raw_line in enumerate(lines, 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith(";") or stripped.startswith("#"):
                    continue

                # PHP-FPM: php_admin_value[session.upload_progress.enabled] = on/off
                #          php_value[session.upload_progress.enabled] = on/off
                # .htaccess: php_flag session.upload_progress.enabled on/off
                #            php_value session.upload_progress.enabled 1/0
                if "session.upload_progress.enabled" in stripped.lower():
                    clean_str = stripped.lower()
                    if any(on_tok in clean_str for on_tok in [" on", "=on", " 1", "=1", "= true", " true"]):
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="YES (設定有効: プール/Web設定で session.upload_progress 有効)",
                            evidence_file=rel_path,
                            line_number=idx,
                            detail=f"{rel_path}:{idx} PHP-FPMプールまたはWeb設定で session.upload_progress.enabled が有効 (On) に設定されています。"
                        )
                    elif any(off_tok in clean_str for off_tok in [" off", "=off", " 0", "=0", "= false", " false"]):
                        fpm_explicit_off = True
                        fpm_off_evidence_file = rel_path
                        fpm_off_line_no = idx
        except Exception:
            continue

    if fpm_explicit_off:
        latest_state = False
        latest_evidence_file = fpm_off_evidence_file
        latest_line_no = fpm_off_line_no

    # If conf.d / php.ini enabled
    if latest_state is True:
        return ConfigVerificationResult(
            is_applicable=True,
            status="YES (設定有効: session.upload_progress 有効)",
            evidence_file=latest_evidence_file,
            line_number=latest_line_no,
            detail=f"{latest_evidence_file}:{latest_line_no} session.upload_progress.enabled が有効 (On) に設定されています。"
        )
    elif latest_state is False:
        # If set to Off in ini, but unparsed pool or .user.ini exists, must be careful
        if pool_and_htaccess_files and not fpm_explicit_off:
            return ConfigVerificationResult(
                is_applicable=True,
                status="外部設定要確認 (プール設定/Web設定による上書き可能性あり)",
                evidence_file=str(pool_and_htaccess_files[0].relative_to(code_dir)),
                detail=(
                    f"{latest_evidence_file}:{latest_line_no} で session.upload_progress.enabled=Off が指定されていますが、"
                    f"上書きしうる設定ファイル（{pool_and_htaccess_files[0].relative_to(code_dir)} 等）が存在します。実環境設定を確認してください。"
                )
            )

        return ConfigVerificationResult(
            is_applicable=True,
            status="NO (設定無効化確認)",
            evidence_file=latest_evidence_file,
            line_number=latest_line_no,
            detail=f"{latest_evidence_file}:{latest_line_no} session.upload_progress.enabled が無効 (Off) に明示設定されています。"
        )
    else:
        # No directive found across all checked php.ini and conf.d: default in PHP 5.4+ is On!
        primary_file = files_evaluated[0] if files_evaluated else "php.ini"
        return ConfigVerificationResult(
            is_applicable=True,
            status="外部設定要確認 (既定値依存: session.upload_progress 未記載)",
            evidence_file=primary_file,
            detail=f"{primary_file}: session.upload_progress.enabled の明示設定がありません（PHP既定では有効）。"
        )


def scan_nginx_conf(code_dir: Path, target_cve: Optional[str] = None) -> Optional[ConfigVerificationResult]:
    """Inspect nginx configuration files for HTTP/2 protocol enablement.
    
    Includes nginx.conf, conf.d/*.conf, sites-enabled/*, sites-available/*, and nginx subdirectories.
    - If ANY file enables HTTP/2 (http2 on; or listen ... http2) -> YES
    - If NO directive is found across configs -> 外部設定要確認 (cannot assume HTTP/1.1 because includes or LB/CDN termination may exist)
    - Only if ALL files explicitly disable HTTP/2 (http2 off;) -> NO
    """
    nginx_conf_files: List[Path] = []
    for root, _, files in os.walk(code_dir):
        rel_root = str(Path(root).relative_to(code_dir)).lower()
        for fname in sorted(files):
            fl = fname.lower()
            if fl == "nginx.conf" or (fl.endswith(".conf") and ("conf.d" in rel_root or "nginx" in rel_root or "sites" in rel_root)):
                nginx_conf_files.append(Path(root) / fname)

    if not nginx_conf_files:
        return None

    yes_results: List[ConfigVerificationResult] = []
    no_results: List[ConfigVerificationResult] = []
    unverified_results: List[ConfigVerificationResult] = []

    for fpath in nginx_conf_files:
        rel_path = str(fpath.relative_to(code_dir))
        try:
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            file_http2_status: Optional[bool] = None  # True: on, False: off, None: absent
            found_line_no = None

            for idx, raw_line in enumerate(lines, 1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # Strip inline comment
                if "#" in stripped:
                    stripped = stripped.split("#")[0].strip()

                # Check for `http2 on;` or `http2 off;`
                if re.search(r"\bhttp2\s+on\b", stripped, re.IGNORECASE):
                    file_http2_status = True
                    found_line_no = idx
                    break
                elif re.search(r"\bhttp2\s+off\b", stripped, re.IGNORECASE):
                    file_http2_status = False
                    found_line_no = idx
                # Check for `listen ... http2`
                elif re.search(r"\blisten\b[^;]*\bhttp2\b", stripped, re.IGNORECASE):
                    file_http2_status = True
                    found_line_no = idx
                    break

            if file_http2_status is True:
                yes_results.append(
                    ConfigVerificationResult(
                        is_applicable=True,
                        status="YES (設定有効: HTTP/2 有効)",
                        evidence_file=rel_path,
                        line_number=found_line_no,
                        detail=f"{rel_path}:{found_line_no} HTTP/2 プロトコルが有効化されています (http2 on / listen ... http2)。"
                    )
                )
            elif file_http2_status is False:
                no_results.append(
                    ConfigVerificationResult(
                        is_applicable=True,
                        status="NO (設定無効化確認)",
                        evidence_file=rel_path,
                        line_number=found_line_no,
                        detail=f"{rel_path}:{found_line_no} HTTP/2 プロトコルが無効 (http2 off) に明示設定されています。"
                    )
                )
            else:
                unverified_results.append(
                    ConfigVerificationResult(
                        is_applicable=True,
                        status="外部設定要確認 (HTTP/2 設定未記載: インフラ/LB終端の要確認)",
                        evidence_file=rel_path,
                        detail=f"{rel_path}: HTTP/2 の明示的設定が見つかりませんでした。外部 include、ロードバランサー、または CDN 側の終端設定を確認してください。"
                    )
                )
        except Exception:
            continue

    # Aggregation
    if yes_results:
        return yes_results[0]
    if unverified_results:
        return unverified_results[0]
    if no_results:
        return no_results[0]

    return None


def inspect_configuration(
    code_dir: Path,
    verification_method: str,
    check_point_yes_no: str,
    target_cve: Optional[str] = None,
    config_check: Optional[str] = None
) -> Optional[ConfigVerificationResult]:
    """Execute target-specific configuration scanner if relevant to the check point.
    
    Prefers explicit `config_check` key if provided.
    Falls back to strict composite heuristic matching only, annotating inferences clearly.
    """
    # 1. Explicit config_check field from structured report
    if config_check:
        if config_check == "tomcat_ajp":
            return scan_tomcat_server_xml(code_dir, target_cve)
        elif config_check == "nginx_http2":
            return scan_nginx_conf(code_dir, target_cve)
        elif config_check == "php_upload_progress":
            return scan_php_ini(code_dir, target_cve)
        else:
            return None

    # 2. Strict composite fallback (annotates detail that inference was used)
    combined = f"{check_point_yes_no} {verification_method}".lower()

    if ("tomcat" in combined or "server.xml" in combined) and any(k in combined for k in ["ajp", "ghostcat", "8009"]):
        res = scan_tomcat_server_xml(code_dir, target_cve)
        if res:
            res.detail = f"【推測振り分け: tomcat_ajp】{res.detail}"
        return res

    if ("php" in combined or "php.ini" in combined) and any(k in combined for k in ["upload_progress", "session.upload_progress"]):
        res = scan_php_ini(code_dir, target_cve)
        if res:
            res.detail = f"【推測振り分け: php_upload_progress】{res.detail}"
        return res

    if ("nginx" in combined or "nginx.conf" in combined) and "http2" in combined:
        if not any(other in combined for other in ["tomcat", "node", "brotli", "apache"]):
            res = scan_nginx_conf(code_dir, target_cve)
            if res:
                res.detail = f"【推測振り分け: nginx_http2】{res.detail}"
            return res

    return None
