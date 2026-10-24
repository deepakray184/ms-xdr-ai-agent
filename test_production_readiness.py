"""Production Readiness & Mock Data Test Suite for Microsoft Defender XDR & Sentinel AI SOC Agent.
Validates all modules, APIs, heuristics, threat scenarios, containment actions, and report generation.
"""

import sys
import unittest
from datetime import datetime
from fastapi.testclient import TestClient

from config import settings
from defender_client import DefenderXDRClient
from ai_analyzer import AISOCAnalyzer
from remediation import RemediationOrchestrator
from ir_report_generator import IncidentReportGenerator
from models import AlertSeverity, EntityType, TriageVerdict
import web_dashboard


class TestProductionReadiness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Force mock mode for test suite
        settings.FORCE_MOCK = True
        cls.client = DefenderXDRClient()
        cls.analyzer = AISOCAnalyzer()
        cls.remediation = RemediationOrchestrator(cls.client)
        cls.report_gen = IncidentReportGenerator(output_dir="incident_reports/test_run")
        cls.web_client = TestClient(web_dashboard.app)

    # -------------------------------------------------------------------------
    # 1. Defender & Sentinel Client Tests
    # -------------------------------------------------------------------------
    def test_01_connectivity_mock_mode(self):
        """Verify client connection diagnostic reports active mock/simulation mode."""
        conn = self.client.test_connection()
        self.assertTrue(conn.get("connected"), "Client should report connected in simulation mode")
        self.assertIn(conn.get("mode"), ("MOCK", "MOCK_FALLBACK"), "Execution mode should be mock")

    def test_02_fetch_all_alerts(self):
        """Verify alert ingestion retrieves both Defender and Sentinel alerts."""
        alerts = self.client.get_alerts()
        self.assertGreaterEqual(len(alerts), 5, "Should retrieve at least 5 mock alerts")

        service_sources = [a.service_source for a in alerts]
        self.assertIn("microsoftDefenderForEndpoint", service_sources)
        self.assertIn("microsoftSentinel", service_sources)
        self.assertIn("microsoftDefenderForCloudApps", service_sources)

    def test_03_fetch_alert_by_id(self):
        """Verify fetching specific alerts by ID and non-existent IDs."""
        alert = self.client.get_alert_by_id("da-9821-lsass-dump")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.id, "da-9821-lsass-dump")
        self.assertEqual(alert.severity, AlertSeverity.HIGH)

        # Non-existent
        fake = self.client.get_alert_by_id("non-existent-alert-id")
        self.assertIsNone(fake)

    def test_04_alert_filtering(self):
        """Verify severity filtering."""
        high_alerts = self.client.get_alerts(severity="high")
        self.assertTrue(all(a.severity == AlertSeverity.HIGH for a in high_alerts))
        self.assertGreater(len(high_alerts), 0)

    # -------------------------------------------------------------------------
    # 2. AI SOC Analyst & Threat Scenarios
    # -------------------------------------------------------------------------
    def test_05_scenario_lsass_dumping(self):
        """Validate Scenario 1: LSASS Credential Theft analysis."""
        alert = self.client.get_alert_by_id("da-9821-lsass-dump")
        report = self.analyzer.analyze_alert(alert)

        self.assertEqual(report.verdict, TriageVerdict.TRUE_POSITIVE)
        self.assertGreaterEqual(report.confidence_score, 90)
        self.assertEqual(report.severity_assessment, AlertSeverity.HIGH)
        self.assertIn("lsass", report.technical_narrative.lower())

        # Check containment actions
        actions = [a.action for a in report.containment_actions]
        self.assertTrue(any("isolate" in a.lower() for a in actions), "Should recommend device isolation")
        self.assertTrue(any("revoke" in a.lower() or "password" in a.lower() for a in actions), "Should recommend password reset/token revocation")

        # Check KQL hunting queries
        tables = [q.table for q in report.hunting_queries]
        self.assertIn("DeviceLogonEvents", tables)
        self.assertIn("DeviceEvents", tables)

    def test_06_scenario_macro_base64_c2(self):
        """Validate Scenario 2: Phishing Macro & Base64 PowerShell execution."""
        alert = self.client.get_alert_by_id("da-8710-phish-macro-c2")
        report = self.analyzer.analyze_alert(alert)

        self.assertEqual(report.verdict, TriageVerdict.TRUE_POSITIVE)
        self.assertGreaterEqual(report.confidence_score, 90)
        # Check that base64 payload was decoded
        self.assertIn("185.220.101.52", report.technical_narrative, "Decoded C2 IP should appear in narrative")

        # Check IOC block recommendation
        actions = [a.action for a in report.containment_actions]
        self.assertTrue(any("block" in a.lower() or "indicator" in a.lower() for a in actions))

        # Check KQL queries
        tables = [q.table for q in report.hunting_queries]
        self.assertIn("EmailAttachmentInfo", tables)
        self.assertIn("DeviceNetworkEvents", tables)

    def test_07_scenario_impossible_travel(self):
        """Validate Scenario 3: Cloud Impossible Travel & Mailbox Forwarding (BEC)."""
        alert = self.client.get_alert_by_id("da-7640-cloud-impossible-travel")
        report = self.analyzer.analyze_alert(alert)

        self.assertIn("Suspicious", report.verdict.value)
        self.assertIn("forwarding", report.technical_narrative.lower())

        # Check containment
        actions = [a.action for a in report.containment_actions]
        self.assertTrue(any("revoke" in a.lower() for a in actions))
        self.assertTrue(any("delete" in a.lower() or "forwarding" in a.lower() for a in actions))

        # Check KQL
        tables = [q.table for q in report.hunting_queries]
        self.assertIn("SigninLogs", tables)
        self.assertIn("CloudAppEvents", tables)

    def test_08_scenario_psexec_admin_fp(self):
        """Validate Scenario 4: Admin PsExec Dual-Use / Low Severity."""
        alert = self.client.get_alert_by_id("da-5120-admin-psexec-fp")
        report = self.analyzer.analyze_alert(alert)

        self.assertEqual(report.severity_assessment, AlertSeverity.LOW)
        self.assertIn("Suspicious", report.verdict.value)
        self.assertIn("psexec", report.technical_narrative.lower())

    def test_09_scenario_sentinel_keyvault_cryptomining(self):
        """Validate Scenario 5: Microsoft Sentinel Key Vault & Rogue Azure VM."""
        alert = self.client.get_alert_by_id("sen-4410-keyvault-cryptominer")
        report = self.analyzer.analyze_alert(alert)

        self.assertEqual(report.verdict, TriageVerdict.TRUE_POSITIVE)
        self.assertGreaterEqual(report.confidence_score, 90)
        self.assertIn("sentinel", report.executive_summary.lower())

        # Verify cloud resource evidence
        entities = [e for e in report.impacted_entities if e.entity_type == EntityType.CLOUD_RESOURCE]
        self.assertGreaterEqual(len(entities), 2, "Should identify Key Vault and VM cloud resources")

        # Verify Sentinel hunting queries
        tables = [q.table for q in report.hunting_queries]
        self.assertIn("AzureDiagnostics", tables, "Should query KeyVault diagnostics")
        self.assertIn("AzureActivity", tables, "Should query ARM Activity logs")

    # -------------------------------------------------------------------------
    # 3. Containment & Remediation Tests
    # -------------------------------------------------------------------------
    def test_10_containment_execution(self):
        """Validate containment execution handler."""
        alert = self.client.get_alert_by_id("da-9821-lsass-dump")
        report = self.analyzer.analyze_alert(alert)
        action = report.containment_actions[0]

        result = self.remediation.execute_action(action)
        self.assertTrue(result.get("success"), "Containment action should succeed")
        self.assertIn("status", result)

    def test_11_powershell_script_generation(self):
        """Validate emergency PowerShell remediation script generator."""
        alert = self.client.get_alert_by_id("da-9821-lsass-dump")
        report = self.analyzer.analyze_alert(alert)

        script = self.remediation.generate_powershell_remediation_script(alert, report.containment_actions)
        self.assertIn("EMERGENCY SOC REMEDIATION SCRIPT", script)
        self.assertIn("Revoke-MgUserSignInSession", script)
        self.assertIn(alert.id, script)

    # -------------------------------------------------------------------------
    # 4. NIST SP 800-61 Incident Response Report Tests
    # -------------------------------------------------------------------------
    def test_12_ir_report_generation_formats(self):
        """Validate Markdown, HTML, and JSON IR reports."""
        alert = self.client.get_alert_by_id("sen-4410-keyvault-cryptominer")
        report = self.analyzer.analyze_alert(alert)

        md = self.report_gen.generate_markdown(alert, report, ticket_id="INC-TEST-001")
        self.assertIn("INCIDENT RESPONSE INVESTIGATION REPORT", md)
        self.assertIn("NIST SP 800-61", md)
        self.assertIn("INC-TEST-001", md)
        self.assertIn("## 5. INCIDENT CHRONOLOGY (TIMELINE)", md)

        html = self.report_gen.generate_html(alert, report, ticket_id="INC-TEST-001")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("AI Triage Verdict", html)
        self.assertIn("INC-TEST-001", html)

        json_data = self.report_gen.generate_json(alert, report, ticket_id="INC-TEST-001")
        self.assertEqual(json_data["incident_reference"], "INC-TEST-001")
        self.assertIn("timeline", json_data)
        self.assertIn("ai_analysis", json_data)

    def test_13_save_reports_to_disk(self):
        """Validate saving all report formats to disk."""
        alert = self.client.get_alert_by_id("da-9821-lsass-dump")
        report = self.analyzer.analyze_alert(alert)

        files = self.report_gen.save_reports(alert, report, ticket_id="INC-PROD-TEST")
        import os
        self.assertTrue(os.path.exists(files["markdown"]), "Markdown report file should exist on disk")
        self.assertTrue(os.path.exists(files["html"]), "HTML report file should exist on disk")
        self.assertTrue(os.path.exists(files["json"]), "JSON report file should exist on disk")

    # -------------------------------------------------------------------------
    # 5. FastAPI Web Endpoints Tests
    # -------------------------------------------------------------------------
    def test_14_api_status(self):
        """Validate /api/status endpoint."""
        res = self.web_client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("azure_connectivity", data)
        self.assertIn("llm_provider", data)

    def test_15_api_alerts_endpoints(self):
        """Validate /api/alerts endpoints."""
        res = self.web_client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)
        alerts = res.json()
        self.assertGreaterEqual(len(alerts), 5)

        # Single alert
        res_single = self.web_client.get("/api/alerts/da-9821-lsass-dump")
        self.assertEqual(res_single.status_code, 200)
        self.assertEqual(res_single.json()["id"], "da-9821-lsass-dump")

        # 404 alert
        res_404 = self.web_client.get("/api/alerts/nonexistent-id")
        self.assertEqual(res_404.status_code, 404)

    def test_16_api_analyze_endpoint(self):
        """Validate POST /api/alerts/{id}/analyze."""
        res = self.web_client.post("/api/alerts/sen-4410-keyvault-cryptominer/analyze")
        self.assertEqual(res.status_code, 200)
        report = res.json()
        self.assertIn("verdict", report)
        self.assertIn("hunting_queries", report)
        self.assertIn("containment_actions", report)

    def test_17_api_containment_execute(self):
        """Validate POST /api/containment/execute."""
        payload = {
            "action": "Isolate Workstation",
            "target_entity": "WKSTN-EXEC-09.corp.contoso.com",
            "priority": "Immediate",
            "rationale": "Test containment"
        }
        res = self.web_client.post("/api/containment/execute", json=payload)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json().get("success"))

    def test_18_api_ir_report_endpoints(self):
        """Validate IR report endpoints on FastAPI."""
        alert_id = "da-9821-lsass-dump"

        # HTML
        res_html = self.web_client.get(f"/api/alerts/{alert_id}/ir-report/html")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn("text/html", res_html.headers["content-type"])

        # Markdown
        res_md = self.web_client.get(f"/api/alerts/{alert_id}/ir-report/markdown")
        self.assertEqual(res_md.status_code, 200)
        self.assertIn("INCIDENT RESPONSE INVESTIGATION REPORT", res_md.text)

        # JSON
        res_json = self.web_client.get(f"/api/alerts/{alert_id}/ir-report/json")
        self.assertEqual(res_json.status_code, 200)
        self.assertIn("timeline", res_json.json())

        # Generate on disk
        res_gen = self.web_client.post(f"/api/alerts/{alert_id}/ir-report/generate?ticket_id=INC-TEST-API")
        self.assertEqual(res_gen.status_code, 200)
        self.assertTrue(res_gen.json()["success"])

    def test_19_dashboard_html_view(self):
        """Validate GET / renders the HTML dashboard correctly."""
        res = self.web_client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/html", res.headers["content-type"])
        self.assertIn("Defender XDR AI SOC Agent", res.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
