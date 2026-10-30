import os
import shutil
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.verifier.config_scanner import (
    inspect_configuration,
    scan_nginx_conf,
    scan_php_ini,
    scan_tomcat_server_xml,
)
from triage_agent.verifier.engine import verify_codebase
from triage_agent.verifier.scanner import remove_xml_comments_from_line, scan_directory_for_patterns


class TestConfigScannerPillar2(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.code_path = Path(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_case_a_nginx_conf_d_http2(self):
        """Case A: nginx.conf has no http2, but conf.d/site.conf has `listen 443 ssl http2` -> YES."""
        nginx_conf = self.code_path / "nginx.conf"
        nginx_conf.write_text("events {}\nhttp {\n  include conf.d/*.conf;\n}\n", encoding="utf-8")

        conf_d = self.code_path / "conf.d"
        conf_d.mkdir()
        site_conf = conf_d / "site.conf"
        site_conf.write_text("server {\n  listen 443 ssl http2;\n  server_name example.com;\n}\n", encoding="utf-8")

        res = scan_nginx_conf(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("YES"))
        self.assertIn("site.conf", res.evidence_file)
        self.assertEqual(res.line_number, 2)

    def test_case_a_nginx_no_http2_returns_unverified(self):
        """Nginx configs without any http2 mention must NOT return NO; must return 外部設定要確認."""
        nginx_conf = self.code_path / "nginx.conf"
        nginx_conf.write_text("events {}\nhttp {\n  server { listen 80; }\n}\n", encoding="utf-8")

        res = scan_nginx_conf(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("外部設定要確認"))
        self.assertIn("HTTP/2 設定未記載", res.status)

    def test_case_c2_multiple_server_xml_order_independent(self):
        """Case C2: Two server.xml files exist. One is protected, the other is unprotected (secretRequired=false).
        
        Regardless of filesystem scanning order, the result must be YES.
        """
        # App 1 in 'aaa' dir (protected)
        dir_a = self.code_path / "aaa"
        dir_a.mkdir()
        server_a = dir_a / "server.xml"
        server_a.write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" secretRequired="true" secret="safe123" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        # App 2 in 'zzz' dir (vulnerable: secretRequired=false)
        dir_z = self.code_path / "zzz"
        dir_z.mkdir()
        server_z = dir_z / "server.xml"
        server_z.write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" secretRequired="false" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        res = scan_tomcat_server_xml(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("YES"))
        self.assertIn("zzz/server.xml", res.evidence_file)

        # Reverse alphabetical directory order to ensure filesystem walk order independence
        shutil.rmtree(dir_a)
        shutil.rmtree(dir_z)

        dir_a2 = self.code_path / "zzz_protected"
        dir_a2.mkdir()
        (dir_a2 / "server.xml").write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" secretRequired="true" secret="safe123" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        dir_z2 = self.code_path / "aaa_vulnerable"
        dir_z2.mkdir()
        (dir_z2 / "server.xml").write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" secretRequired="false" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        res2 = scan_tomcat_server_xml(self.code_path)
        self.assertIsNotNone(res2)
        self.assertTrue(res2.status.startswith("YES"))
        self.assertIn("aaa_vulnerable/server.xml", res2.evidence_file)

    def test_case_b2_php_ini_template_skipped(self):
        """Case B2: Only php.ini-production or php.ini-development exists.
        
        These are distribution templates, not active configs. scan_php_ini must ignore them.
        """
        tpl = self.code_path / "php.ini-production"
        tpl.write_text("session.upload_progress.enabled = Off\n", encoding="utf-8")

        res = scan_php_ini(self.code_path)
        self.assertIsNone(res, "Distribution templates must not be treated as active php.ini")

    def test_case_g_php_conf_d_overrides_php_ini_to_on(self):
        """Case G: php.ini sets Off, but conf.d/99-app.ini overrides to On.
        
        PHP evaluates conf.d/*.ini alphabetically after php.ini (last wins). Result must be YES.
        """
        php_ini = self.code_path / "php.ini"
        php_ini.write_text("session.upload_progress.enabled = Off\n", encoding="utf-8")

        conf_d = self.code_path / "conf.d"
        conf_d.mkdir()
        override_ini = conf_d / "99-app.ini"
        override_ini.write_text("session.upload_progress.enabled = On\n", encoding="utf-8")

        res = scan_php_ini(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("YES"))
        self.assertIn("99-app.ini", res.evidence_file)
        self.assertEqual(res.line_number, 1)

    def test_php_ini_off_with_fpm_pool_config_triggers_unverified(self):
        """If php.ini sets Off, but an unverified PHP-FPM pool config exists, must return 外部設定要確認."""
        php_ini = self.code_path / "php.ini"
        php_ini.write_text("session.upload_progress.enabled = Off\n", encoding="utf-8")

        fpm_dir = self.code_path / "php-fpm.d"
        fpm_dir.mkdir()
        www_conf = fpm_dir / "www.conf"
        www_conf.write_text("; Pool configuration with custom php_value\n[www]\nlisten = 9000\n", encoding="utf-8")

        res = scan_php_ini(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("外部設定要確認"))
        self.assertIn("上書き可能性", res.status)

    def test_multiline_ajp_connector_line_number(self):
        """Multiline <Connector ... > block must accurately report the opening tag line number."""
        server_xml = self.code_path / "server.xml"
        server_xml.write_text(
            '<Server>\n'
            '  <Service>\n'
            '    <Connector\n'
            '       port="8009"\n'
            '       protocol="AJP/1.3"\n'
            '       secretRequired="false" />\n'
            '  </Service>\n'
            '</Server>',
            encoding="utf-8"
        )

        res = scan_tomcat_server_xml(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("YES"))
        self.assertEqual(res.line_number, 3, "Opening <Connector line should be reported")

    def test_inference_annotation_when_config_check_omitted(self):
        """When config_check is omitted, heuristic inference must annotate detail with 【推測振り分け】."""
        server_xml = self.code_path / "server.xml"
        server_xml.write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" secretRequired="false" />'
            '</Service></Server>',
            encoding="utf-8"
        )
        res = inspect_configuration(
            code_dir=self.code_path,
            verification_method="server.xml で AJP コネクタの secretRequired を確認",
            check_point_yes_no="AJP コネクタを有効にしているか",
            config_check=None
        )
        self.assertIsNotNone(res)
        self.assertIn("【推測振り分け: tomcat_ajp】", res.detail)

    def test_case_d_tomcat_http2_not_intercepted_by_ajp_checker(self):
        """Case D: Check point asks about Tomcat HTTP/2 (Http2Protocol).
        
        Even though server.xml is present without AJP connector, it should NOT return AJP NO.
        Instead, codebase search for `Http2Protocol` should execute and find the active code -> YES.
        """
        server_xml = self.code_path / "server.xml"
        server_xml.write_text(
            '<Server><Service><Connector port="8080" protocol="HTTP/1.1" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        # Codebase uses Http2Protocol in Java configuration
        java_dir = self.code_path / "src" / "main" / "java"
        java_dir.mkdir(parents=True)
        java_file = java_dir / "TomcatConfig.java"
        java_file.write_text(
            'public class TomcatConfig {\n'
            '  public void init() {\n'
            '    connector.addUpgradeProtocol(new Http2Protocol());\n'
            '  }\n'
            '}\n',
            encoding="utf-8"
        )

        report = TriageReport(
            report_title="Tomcat Triage Test",
            summary="Test",
            notices=[
                TriageNotice(
                    product_name="Apache Tomcat",
                    component_name="tomcat",
                    announcement_date="2026-10-30",
                    conclusion="Test",
                    fixed_versions="10.1.20",
                    severity_note="Important",
                    check_points=[
                        CheckPointItem(
                            check_point_id="tomcat-cve-2026-test-cp1",
                            target_or_cve="CVE-2026-0002",
                            content_summary="Tomcat HTTP/2 processing vulnerability",
                            affected_versions="< 10.1.20",
                            check_point_yes_no="HTTP/2（Http2Protocol）を有効にしているか",
                            verification_method="server.xml またはコード内で `Http2Protocol` を設定しているか確認"
                        )
                    ]
                )
            ]
        )

        audit = verify_codebase(report, str(self.code_path))
        cp_result = audit.notice_results[0].results[0]
        self.assertTrue(cp_result.status.startswith("YES"))
        self.assertIn("Http2Protocol", cp_result.reasoning)

    def test_case_e_server_xml_malformed_xml_returns_unverified(self):
        """Case E: server.xml contains undeclared entity (&nbsp;) or syntax error -> 外部設定要確認."""
        server_xml = self.code_path / "server.xml"
        server_xml.write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" description="AJP&nbsp;Connector" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        res = scan_tomcat_server_xml(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("外部設定要確認"))
        self.assertIn("構文解析エラー", res.status)
        self.assertIn("server.xml", res.evidence_file)

    def test_legacy_tomcat_required_secret(self):
        """Legacy Tomcat 9.0.30 and older attribute `requiredSecret` must be recognized as protection."""
        server_xml = self.code_path / "server.xml"
        server_xml.write_text(
            '<Server><Service><Connector protocol="AJP/1.3" port="8009" requiredSecret="mySecretPassword" />'
            '</Service></Server>',
            encoding="utf-8"
        )

        res = scan_tomcat_server_xml(self.code_path)
        self.assertIsNotNone(res)
        self.assertTrue(res.status.startswith("NO (設定無効化確認)"))
        self.assertIn("requiredSecret", res.detail)

    def test_xml_comment_multiple_per_line(self):
        """Multiple XML comments on a single line must all be stripped."""
        line = '<!-- c1 --> <Connector protocol="AJP/1.3" /> <!-- c2 --> <Bar />'
        clean_line, in_comment = remove_xml_comments_from_line(line, False)
        self.assertFalse(in_comment)
        self.assertNotIn("c1", clean_line)
        self.assertNotIn("c2", clean_line)
        self.assertIn('<Connector protocol="AJP/1.3" />', clean_line)
        self.assertIn("<Bar />", clean_line)

    def test_explicit_config_check_dispatch(self):
        """Explicit `config_check` attribute in CheckPointItem routes cleanly."""
        res = inspect_configuration(
            code_dir=self.code_path,
            verification_method="anything",
            check_point_yes_no="anything",
            config_check="non_existent_check"
        )
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
