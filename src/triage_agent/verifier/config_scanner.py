"""Specialized configuration file scanner (XML, INI, Nginx/Apache Conf, Properties).

Implements deterministic inspection for middleware and infrastructure configurations (ADR-019),
ensuring comments are completely stripped and directive values are parsed semantically.
"""

import configparser
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class ConfigVerificationResult:
    is_applicable: bool
    status: str  # "YES (設定有効)" | "NO (設定無効化確認)" | "外部設定要確認"
    evidence_file: Optional[str] = None
    line_number: Optional[int] = None
    detail: str = ""


# Known config file names
CONFIG_FILENAMES = {
    "server.xml", "php.ini", "nginx.conf", "httpd.conf", "apache2.conf",
    "application.properties", "application.yml", "application.yaml"
}


def is_config_inspection(verification_method: str, check_point_yes_no: str) -> bool:
    """Determine whether this check point targets middleware/application configuration files."""
    combined = f"{check_point_yes_no} {verification_method}".lower()
    for name in CONFIG_FILENAMES:
        if name in combined:
            return True
    if any(k in combined for k in ["<connector", "ajp", "upload_progress", "http2 on", "session.upload_progress"]):
        return True
    return False


def scan_tomcat_server_xml(code_dir: Path, target_cve: Optional[str] = None) -> Optional[ConfigVerificationResult]:
    """Inspect Tomcat server.xml for AJP or sensitive connector/realm configurations."""
    for root, _, files in os.walk(code_dir):
        for fname in files:
            if fname.lower() == "server.xml":
                fpath = Path(root) / fname
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
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="NO (設定無効化確認)",
                            evidence_file=rel_path,
                            detail=f"{rel_path}: AJP/1.3 コネクタは未定義またはコメントアウトされています（非該当）。"
                        )

                    # AJP connector found. Check if protected with secret / secretRequired
                    for conn in ajp_connectors:
                        port = conn.get("port", "8009")
                        secret = conn.get("secret")
                        secret_required = conn.get("secretRequired", "").lower()

                        if secret_required == "true" and secret:
                            # Protected
                            continue
                        else:
                            # Vulnerable / active without secret protection
                            # Find approximate line number in raw file
                            raw_lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                            line_no = 1
                            for idx, line in enumerate(raw_lines, 1):
                                if "AJP" in line and "<Connector" in line:
                                    line_no = idx
                                    break
                            return ConfigVerificationResult(
                                is_applicable=True,
                                status="YES (設定有効: AJPコネクタ有効かつ認証未保護)",
                                evidence_file=rel_path,
                                line_number=line_no,
                                detail=(
                                    f"{rel_path}:{line_no} AJP/1.3 コネクタ（port={port}）が有効化されており、"
                                    f"secret/secretRequired による保護が未設定です（Ghostcat 影響対象）。"
                                )
                            )

                    return ConfigVerificationResult(
                        is_applicable=True,
                        status="NO (設定無効化確認)",
                        evidence_file=rel_path,
                        detail=f"{rel_path}: AJP コネクタに secretRequired / secret が設定されており保護されています。"
                    )
                except Exception as e:
                    # XML parse failed (syntax error or corrupted)
                    continue

    return None


def scan_php_ini(code_dir: Path, target_cve: Optional[str] = None) -> Optional[ConfigVerificationResult]:
    """Inspect php.ini for session.upload_progress or unsafe PHP runtime directives."""
    for root, _, files in os.walk(code_dir):
        for fname in files:
            if fname.lower() in ("php.ini", "php.ini-production", "php.ini-development"):
                fpath = Path(root) / fname
                rel_path = str(fpath.relative_to(code_dir))
                try:
                    lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                    upload_progress_enabled = None
                    line_no = None

                    for idx, raw_line in enumerate(lines, 1):
                        stripped = raw_line.strip()
                        # Skip comments and empty lines
                        if not stripped or stripped.startswith(";") or stripped.startswith("#"):
                            continue

                        # Match session.upload_progress.enabled = ...
                        if "=" in stripped:
                            key, val = [p.strip() for p in stripped.split("=", 1)]
                            if key.lower() == "session.upload_progress.enabled":
                                val_clean = val.lower().split(";")[0].split("#")[0].strip()
                                upload_progress_enabled = val_clean in ("on", "1", "yes", "true")
                                line_no = idx

                    if upload_progress_enabled is True:
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="YES (設定有効: session.upload_progress 有効)",
                            evidence_file=rel_path,
                            line_number=line_no,
                            detail=f"{rel_path}:{line_no} session.upload_progress.enabled が有効 (On) に設定されています。"
                        )
                    elif upload_progress_enabled is False:
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="NO (設定無効化確認)",
                            evidence_file=rel_path,
                            line_number=line_no,
                            detail=f"{rel_path}:{line_no} session.upload_progress.enabled が無効 (Off) に明示設定されています。"
                        )
                    else:
                        # Directive not present in php.ini: default in PHP 5.4+ is On!
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="外部設定要確認 (既定値依存: session.upload_progress 未記載)",
                            evidence_file=rel_path,
                            detail=f"{rel_path}: session.upload_progress.enabled の明示設定がありません（PHP既定では有効）。"
                        )
                except Exception:
                    continue

    return None


def scan_nginx_conf(code_dir: Path, target_cve: Optional[str] = None) -> Optional[ConfigVerificationResult]:
    """Inspect nginx.conf or conf.d/*.conf for HTTP/2 protocol enablement."""
    for root, _, files in os.walk(code_dir):
        for fname in files:
            if fname.lower() == "nginx.conf" or (fname.lower().endswith(".conf") and "nginx" in str(root).lower()):
                fpath = Path(root) / fname
                rel_path = str(fpath.relative_to(code_dir))
                try:
                    lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
                    http2_enabled = None
                    line_no = None

                    for idx, raw_line in enumerate(lines, 1):
                        stripped = raw_line.strip()
                        # Skip comments and empty lines
                        if not stripped or stripped.startswith("#"):
                            continue

                        # Clean inline comments
                        if "#" in stripped:
                            stripped = stripped.split("#")[0].strip()

                        # Check for `http2 on;` or `http2 off;`
                        if re.search(r"\bhttp2\s+on\b", stripped, re.IGNORECASE):
                            http2_enabled = True
                            line_no = idx
                            break
                        elif re.search(r"\bhttp2\s+off\b", stripped, re.IGNORECASE):
                            http2_enabled = False
                            line_no = idx
                        # Check for `listen ... http2`
                        elif re.search(r"\blisten\b[^;]*\bhttp2\b", stripped, re.IGNORECASE):
                            http2_enabled = True
                            line_no = idx
                            break

                    if http2_enabled is True:
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="YES (設定有効: HTTP/2 有効)",
                            evidence_file=rel_path,
                            line_number=line_no,
                            detail=f"{rel_path}:{line_no} HTTP/2 プロトコルが有効化されています (http2 on / listen ... http2)。"
                        )
                    elif http2_enabled is False:
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="NO (設定無効化確認)",
                            evidence_file=rel_path,
                            line_number=line_no,
                            detail=f"{rel_path}:{line_no} HTTP/2 プロトコルが無効 (http2 off) に明示設定されています。"
                        )
                    else:
                        # http2 directive not found
                        return ConfigVerificationResult(
                            is_applicable=True,
                            status="NO (設定無効化確認)",
                            evidence_file=rel_path,
                            detail=f"{rel_path}: HTTP/2 の有効化設定（http2 on / listen ... http2）は見つかりませんでした（HTTP/1.1 のみ）。"
                        )
                except Exception:
                    continue

    return None


def inspect_configuration(
    code_dir: Path,
    verification_method: str,
    check_point_yes_no: str,
    target_cve: Optional[str] = None
) -> Optional[ConfigVerificationResult]:
    """Execute target-specific configuration scanner if relevant to the check point."""
    combined = f"{check_point_yes_no} {verification_method}".lower()

    if "server.xml" in combined or "<connector" in combined or "ajp" in combined or "ghostcat" in combined:
        res = scan_tomcat_server_xml(code_dir, target_cve)
        if res:
            return res

    if "php.ini" in combined or "upload_progress" in combined:
        res = scan_php_ini(code_dir, target_cve)
        if res:
            return res

    if "nginx.conf" in combined or "http2" in combined:
        res = scan_nginx_conf(code_dir, target_cve)
        if res:
            return res

    return None
