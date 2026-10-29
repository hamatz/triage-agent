"""Lightweight, zero-dependency Web GUI server for triage-agent.

Runs a local web dashboard using Python's standard library http.server,
providing an interactive interface to run triage scans, inspect reports,
run codebase verifications, and draft audit sign-offs.
"""

import argparse
import getpass
import json
import os
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import resources
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from rich.console import Console

from triage_agent.config import get_model_name, is_llm_configured
from triage_agent.pipeline import execute_triage_pipeline
from triage_agent.schemas import TriageReport
from triage_agent.verifier import CodebaseAuditReport

console = Console()

# Cryptographically secure random CSRF token generated on server startup
SERVER_CSRF_TOKEN = secrets.token_hex(24)

DEFAULT_OUTPUT_DIR = Path.cwd().resolve() / "triage-output"


def resolve_safe_path(path_str: str, base_dir: Optional[Path] = None) -> Path:
    """Ensure a user-supplied path stays strictly within the authorized base directory.

    Prevents directory traversal (e.g. ../../) and arbitrary filesystem overwrites.
    """
    if not path_str or not path_str.strip():
        raise ValueError("パスが指定されていません。")
    if base_dir is None:
        base_dir = Path.cwd().resolve()
    resolved = (base_dir / path_str.strip()).resolve()
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        raise PermissionError(
            f"セキュリティ制限: 作業ディレクトリ外のファイルへのアクセスは拒否されました ('{path_str}')"
        )
    return resolved


def resolve_safe_output_path(path_str: str, allowed_extensions: tuple = (".md", ".json", ".ics", ".csv")) -> Path:
    """Ensure a save path stays strictly within the dedicated 'triage-output/' directory
    and has an authorized extension (.md, .json, .ics).

    Prevents source code overwriting and directory traversal (ADR-013).
    """
    if not path_str or not path_str.strip():
        raise ValueError("出力ファイル名が指定されていません。")

    clean_name = path_str.strip()
    p = Path(clean_name)
    suffix = p.suffix.lower()
    if suffix not in allowed_extensions:
        raise ValueError(
            f"許可されていない拡張子です ('{suffix}')。許可拡張子: {', '.join(allowed_extensions)}"
        )

    if p.is_absolute():
        raise PermissionError("絶対パスでのファイル保存はセキュリティ上禁止されています。")

    out_dir = DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    parts = list(p.parts)
    if parts and parts[0] in ("triage-output", "./triage-output"):
        parts = parts[1:]

    resolved = (out_dir / Path(*parts)).resolve()
    try:
        resolved.relative_to(out_dir)
    except ValueError:
        raise PermissionError(
            f"セキュリティ制限: 出力専用ディレクトリ (triage-output/) 外へのファイル書き込みは拒否されました ('{path_str}')"
        )
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def resolve_safe_load_path(path_str: str, allowed_extensions: tuple = (".json",)) -> Path:
    """Ensure a report/attestation load path has an authorized extension (.json)
    and stays within the authorized workspace, preventing arbitrary file reads.
    """
    if not path_str or not path_str.strip():
        raise ValueError("読込ファイル名が指定されていません。")

    clean_name = path_str.strip()
    p = Path(clean_name)
    suffix = p.suffix.lower()
    if suffix not in allowed_extensions:
        raise ValueError(
            f"許可されていない拡張子です ('{suffix}')。許可拡張子: {', '.join(allowed_extensions)}"
        )

    if p.is_absolute():
        raise PermissionError("絶対パスでのファイル読み込みは禁止されています。")

    # If it exists directly in triage-output/
    out_dir = DEFAULT_OUTPUT_DIR
    candidate_in_out = (out_dir / p.name).resolve()
    if candidate_in_out.exists():
        return candidate_in_out

    # Workspace directory check
    base_dir = Path.cwd().resolve()
    resolved = (base_dir / clean_name).resolve()
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        raise PermissionError(
            f"セキュリティ制限: 作業ディレクトリ外のファイルへのアクセスは拒否されました ('{path_str}')"
        )

    # Disallow loading files from inside source tree (src/)
    try:
        resolved.relative_to(base_dir / "src")
        raise PermissionError(f"セキュリティ制限: ソースコードディレクトリ内のファイル読み込みは拒否されました ('{path_str}')")
    except ValueError:
        pass

    return resolved


def load_ui_template() -> str:
    """Load the index.html template from package resources."""
    try:
        ref = resources.files("triage_agent.ui").joinpath("templates", "index.html")
        return ref.read_text(encoding="utf-8")
    except Exception:
        # Fallback for direct local file execution
        fallback_path = Path(__file__).parent / "templates" / "index.html"
        return fallback_path.read_text(encoding="utf-8")


def load_static_asset(filename: str) -> Optional[bytes]:
    """Load static asset bytes from package resources safely."""
    # Prevent traversal in static assets
    safe_name = Path(filename).name
    try:
        ref = resources.files("triage_agent.ui").joinpath("static", safe_name)
        return ref.read_bytes()
    except Exception:
        fallback_path = Path(__file__).parent / "static" / safe_name
        if fallback_path.exists():
            return fallback_path.read_bytes()
    return None


def get_bundled_html() -> str:
    """Return full bundled HTML containing embedded CSS and JS (for compatibility and testing)."""
    html = load_ui_template()
    css_bytes = load_static_asset("style.css")
    js_bytes = load_static_asset("app.js")
    css_text = css_bytes.decode("utf-8") if css_bytes else ""
    js_text = js_bytes.decode("utf-8") if js_bytes else ""

    bundled = html.replace(
        '<link rel="stylesheet" href="/static/style.css">',
        f"<style>\n{css_text}\n</style>"
    ).replace(
        '<script src="/static/app.js"></script>',
        f"<script>\n{js_text}\n</script>"
    )
    return bundled


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for snappy UI responsiveness."""
    daemon_threads = True


class TriageDashboardHandler(BaseHTTPRequestHandler):
    """Secure HTTP request handler for the triage-agent dashboard."""

    def end_headers(self):
        """Inject robust security headers on all responses (OWASP ASVS / CSP / Clickjacking)."""
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def _is_host_allowed(self) -> bool:
        """Validate Host header against allowed local addresses to prevent DNS rebinding."""
        server_port = getattr(self.server, "server_port", 8080)
        allowed_hosts = {
            f"127.0.0.1:{server_port}",
            f"localhost:{server_port}",
            "127.0.0.1",
            "localhost",
        }
        host_header = self.headers.get("Host", "").strip()
        return bool(host_header and host_header in allowed_hosts)

    def do_GET(self):
        # 1. Host verification to prevent DNS rebinding attacks
        if not self._is_host_allowed():
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"error": f"アクセス拒否: 不正な Host ヘッダーです ({self.headers.get('Host', '')})"},
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            return

        clean_path = urlsplit(self.path).path

        if clean_path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            default_reviewer = f"{getpass.getuser()} (システム担当)"
            html_content = load_ui_template().replace(
                "__CSRF_TOKEN__", SERVER_CSRF_TOKEN
            ).replace("__DEFAULT_REVIEWER__", default_reviewer)
            self.wfile.write(html_content.encode("utf-8"))

        elif clean_path.startswith("/static/"):
            filename = clean_path[len("/static/"):]
            asset_bytes = load_static_asset(filename)
            if asset_bytes is None:
                self.send_error(404, "Asset Not Found")
                return

            if filename.endswith(".css"):
                content_type = "text/css; charset=utf-8"
            elif filename.endswith(".js"):
                content_type = "text/javascript; charset=utf-8"
            else:
                content_type = "application/octet-stream"

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(asset_bytes)

        elif clean_path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            status = {
                "is_llm_configured": is_llm_configured(),
                "model": get_model_name(),
                "cwd": str(Path.cwd()),
                "default_reviewer": f"{getpass.getuser()} (システム担当)",
            }
            self.wfile.write(json.dumps(status, ensure_ascii=False).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        # 1. Enforce Content-Type check (application/json only to force CORS preflight)
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            self.send_response(415)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "Content-Type must be application/json"}, ensure_ascii=False).encode("utf-8")
            )
            return

        # 2. Origin & Host verification (Strict localhost/127.0.0.1 validation)
        if not self._is_host_allowed():
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"error": f"アクセス拒否: 不正な Host ヘッダーです ({self.headers.get('Host', '')})"},
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            return

        server_port = getattr(self.server, "server_port", 8080)
        origin_header = self.headers.get("Origin", "").strip()
        if origin_header:
            allowed_origins = {
                f"http://127.0.0.1:{server_port}",
                f"http://localhost:{server_port}",
            }
            if origin_header not in allowed_origins:
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {"error": f"アクセス拒否: 外部サイトからのクロスオリジンリクエストです ({origin_header})"},
                        ensure_ascii=False,
                    ).encode("utf-8")
                )
                return

        # 3. Read body safely
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)
        try:
            req_data = json.loads(post_body.decode("utf-8"))
        except Exception:
            req_data = {}

        # 4. Enforce CSRF token verification
        client_token = self.headers.get("X-CSRF-Token") or req_data.get("csrf_token")
        if not client_token or client_token != SERVER_CSRF_TOKEN:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "アクセス拒否: CSRFトークンが無効または欠落しています。"}, ensure_ascii=False).encode(
                    "utf-8"
                )
            )
            return

        clean_path = urlsplit(self.path).path
        if clean_path in ("/api/run", "/api/run-stream"):
            is_stream = (clean_path == "/api/run-stream")
            mode = req_data.get("mode", "demo")
            sbom_path = req_data.get("sbom", "sample_sbom.json").strip()
            code_dir = req_data.get("code_dir", "").strip() or None
            audit_file = req_data.get("audit_file", "sample_audit_signoff.json").strip() or None

            try:
                # Restrict paths strictly within authorized workspace
                safe_sbom = str(resolve_safe_path(sbom_path)) if mode != "demo" else sbom_path
                safe_code = str(resolve_safe_path(code_dir)) if code_dir else None
                safe_audit = str(resolve_safe_path(audit_file)) if audit_file else None

                if is_stream:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("X-Accel-Buffering", "no")
                    self.end_headers()

                    def send_progress(msg: str, percent: int = 0, phase: str = "Init", **kwargs):
                        evt = {
                            "type": "progress",
                            "message": msg,
                            "percent": percent,
                            "phase": phase,
                            **kwargs,
                        }
                        try:
                            self.wfile.write(f"data: {json.dumps(evt, ensure_ascii=False)}\n\n".encode("utf-8"))
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            pass

                    triage_report, audit_report = execute_triage_pipeline(
                        sbom_path=safe_sbom,
                        mode=mode,
                        code_dir=safe_code,
                        audit_file_path=safe_audit,
                        progress_callback=send_progress,
                    )

                    complete_evt = {
                        "type": "complete",
                        "report": triage_report.model_dump(),
                        "audit": audit_report.model_dump() if audit_report else None,
                    }
                    self.wfile.write(f"data: {json.dumps(complete_evt, ensure_ascii=False)}\n\n".encode("utf-8"))
                    self.wfile.flush()

                else:
                    triage_report, audit_report = execute_triage_pipeline(
                        sbom_path=safe_sbom,
                        mode=mode,
                        code_dir=safe_code,
                        audit_file_path=safe_audit,
                    )

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    response_payload = {
                        "report": triage_report.model_dump(),
                        "audit": audit_report.model_dump() if audit_report else None,
                    }
                    self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode("utf-8"))

            except Exception as e:
                if is_stream:
                    err_evt = {"type": "error", "error": str(e)}
                    try:
                        self.wfile.write(f"data: {json.dumps(err_evt, ensure_ascii=False)}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                else:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/create-signoff":
            audit_file_path = req_data.get("audit_file", "sample_audit_signoff.json").strip()
            attestation_data = req_data.get("attestation", {})

            try:
                safe_audit_path = resolve_safe_load_path(audit_file_path, allowed_extensions=(".json",))
                existing_attestations = []
                if safe_audit_path.exists():
                    try:
                        raw = json.loads(safe_audit_path.read_text(encoding="utf-8"))
                        if isinstance(raw, dict) and "attestations" in raw:
                            existing_attestations = raw["attestations"]
                        elif isinstance(raw, list):
                            existing_attestations = raw
                    except Exception:
                        existing_attestations = []

                # Replace or append attestation for the same check_point_id
                cp_id = attestation_data.get("check_point_id")
                updated = False
                for idx, item in enumerate(existing_attestations):
                    if item.get("check_point_id") == cp_id:
                        existing_attestations[idx] = attestation_data
                        updated = True
                        break
                if not updated:
                    existing_attestations.append(attestation_data)

                # Write back safely to the authorized audit file
                safe_audit_path.write_text(
                    json.dumps({"attestations": existing_attestations}, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode("utf-8"))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/save-report":
            report_data = req_data.get("report")
            audit_data = req_data.get("audit")
            output_md = req_data.get("output_md", "triage_report.md")
            output_json = req_data.get("output_json", "triage_report.json")
            verify_output = req_data.get("verify_output", "verification_audit_report.md")

            if not report_data:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "レポートデータが空です。"}, ensure_ascii=False).encode("utf-8"))
                return

            try:
                from triage_agent.cli import format_report_markdown
                from triage_agent.verifier import format_verification_markdown

                saved_files = []
                report_obj = TriageReport.model_validate(report_data)
                audit_obj = CodebaseAuditReport.model_validate(audit_data) if audit_data else None

                md_content = format_report_markdown(report_obj) if output_md else ""
                json_content = report_obj.model_dump_json(indent=2)
                audit_content = format_verification_markdown(audit_obj) if (audit_obj and verify_output) else ""

                if output_md:
                    safe_md = resolve_safe_output_path(output_md, allowed_extensions=(".md",))
                    safe_md.write_text(md_content, encoding="utf-8")
                    saved_files.append(str(safe_md.relative_to(Path.cwd().resolve())))

                if output_json:
                    safe_json = resolve_safe_output_path(output_json, allowed_extensions=(".json",))
                    safe_json.write_text(json_content, encoding="utf-8")
                    saved_files.append(str(safe_json.relative_to(Path.cwd().resolve())))

                if audit_obj and verify_output:
                    safe_audit = resolve_safe_output_path(verify_output, allowed_extensions=(".md",))
                    safe_audit.write_text(audit_content, encoding="utf-8")
                    saved_files.append(str(safe_audit.relative_to(Path.cwd().resolve())))

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "success": True,
                        "saved_files": saved_files,
                        "md_content": md_content,
                        "json_content": json_content,
                        "audit_content": audit_content,
                    }, ensure_ascii=False).encode("utf-8")
                )

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/load-report":
            report_path_str = req_data.get("report_path", "triage_report.json").strip()
            code_dir = req_data.get("code_dir", "").strip() or None
            audit_file = req_data.get("audit_file", "sample_audit_signoff.json").strip() or None

            try:
                safe_report_path = resolve_safe_load_path(report_path_str, allowed_extensions=(".json",))
                if not safe_report_path.exists():
                    raise FileNotFoundError(f"レポートファイルが見つかりません: '{report_path_str}'")

                raw_text = safe_report_path.read_text(encoding="utf-8")
                report_dict = json.loads(raw_text)
                report_obj = TriageReport.model_validate(report_dict)

                audit_report = None
                if code_dir or audit_file:
                    from triage_agent.verifier import verify_codebase
                    safe_code = str(resolve_safe_path(code_dir)) if code_dir else None
                    safe_audit = str(resolve_safe_load_path(audit_file, allowed_extensions=(".json",))) if audit_file else None
                    safe_audit = str(resolve_safe_path(audit_file)) if audit_file else None
                    audit_report = verify_codebase(
                        report_obj,
                        code_dir_path=safe_code,
                        audit_file_path=safe_audit,
                    )

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                response_payload = {
                    "success": True,
                    "report": report_obj.model_dump(),
                    "audit": audit_report.model_dump() if audit_report else None,
                    "loaded_from": str(safe_report_path.name),
                }
                self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode("utf-8"))

            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/export-calendar":
            report_data = req_data.get("report")
            if not report_data:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "レポートデータが空です。"}, ensure_ascii=False).encode("utf-8"))
                return
            try:
                from triage_agent.tools.calendar import generate_icalendar
                report_obj = TriageReport.model_validate(report_data)
                ics_text = generate_icalendar(report_obj.pre_announcements)
                self.send_response(200)
                self.send_header("Content-Type", "text/calendar; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="triage_calendar.ics"')
                self.end_headers()
                self.wfile.write(ics_text.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/export-checklist":
            report_data = req_data.get("report")
            if not report_data:
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "レポートデータが空です。"}, ensure_ascii=False).encode("utf-8"))
                return
            try:
                from triage_agent.tools.vendor_workflow import export_checklist_csv
                report_obj = TriageReport.model_validate(report_data)
                csv_text, out_p = export_checklist_csv(report_obj)
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="vendor_checklist.csv"')
                self.end_headers()
                self.wfile.write(csv_text.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/import-checklist":
            csv_content = req_data.get("csv_content")
            csv_path_str = req_data.get("csv_path")
            audit_file_str = req_data.get("audit_file", "sample_audit_signoff.json")

            try:
                from triage_agent.tools.vendor_workflow import import_vendor_checklist
                import tempfile

                if csv_content:
                    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", encoding="utf-8") as tf:
                        tf.write(csv_content)
                        tmp_path = tf.name
                    try:
                        count, audit_p = import_vendor_checklist(tmp_path, audit_file_str)
                    finally:
                        if os.path.exists(tmp_path):
                            os.remove(tmp_path)
                elif csv_path_str:
                    safe_csv_path = resolve_safe_load_path(csv_path_str, allowed_extensions=(".csv",))
                    count, audit_p = import_vendor_checklist(str(safe_csv_path), audit_file_str)
                else:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "CSVデータまたはCSVファイルパスが指定されていません。"}, ensure_ascii=False).encode("utf-8"))
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "success": True,
                        "imported_count": count,
                        "audit_file": str(audit_p.resolve()),
                    }, ensure_ascii=False).encode("utf-8")
                )
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif clean_path == "/api/workflow-metrics":
            try:
                from triage_agent.tools.vendor_workflow import get_workflow_metrics
                metrics = get_workflow_metrics()
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps(metrics, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))

        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        # Mute excessive polling logs
        pass


def run_gui(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True):
    """Launch the Web GUI dashboard server."""
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, TriageDashboardHandler)
    url = f"http://{host}:{port}"

    console.print(
        f"[bold green]🚀 triage-agent Web Dashboard 起動中...[/bold green]\n"
        f"URL: [bold cyan]{url}[/bold cyan] (Ctrl+C で停止)\n"
    )

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]ダッシュボードサーバーを停止しました。[/yellow]")
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="triage-agent Web Dashboard GUI")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")

    args = parser.parse_args()
    run_gui(host=args.host, port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
