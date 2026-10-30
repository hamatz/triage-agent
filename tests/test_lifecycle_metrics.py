"""Tests for Lifecycle Metrics and MTTR Tracking (v0.3.1 / ADR-019)."""

from datetime import datetime, timezone, timedelta
import tempfile
import unittest
from pathlib import Path
import json

from triage_agent.tools.lifecycle_metrics import (
    calculate_case_metrics,
    is_off_hours_jst,
    load_user_baselines,
)


class TestLifecycleMetrics(unittest.TestCase):
    """Test suite for lifecycle metrics, off-hours detection, and user-supplied baseline comparison."""

    def test_default_no_baselines(self):
        """Without user-provided baselines, engine must NOT compute time-saved or percentage (No fabricated truth)."""
        metrics = calculate_case_metrics(
            t_minus_1_announced="2026-10-20T10:00:00Z",
            t0_detected="2026-10-20T11:00:00Z",
            t1_triaged="2026-10-20T12:00:00Z",
            t2_dispatched="2026-10-20T14:00:00Z",
            t3_attested="2026-10-21T10:00:00Z",
            user_baselines=None,
        )

        self.assertEqual(metrics["lead_time_announce_to_dispatch_hours"], 4.0)
        self.assertEqual(metrics["turnaround_dispatch_to_attest_hours"], 20.0)
        self.assertEqual(metrics["total_lead_time_hours"], 24.0)
        self.assertIsNone(metrics["baseline_average_hours"])
        self.assertEqual(metrics["baseline_count"], 0)
        self.assertIsNone(metrics["lead_time_saved_hours"])
        self.assertIsNone(metrics["reduction_percentage"])

    def test_user_supplied_baselines(self):
        """When user provides verified internal baselines with tickets/evidence, computes reduction accurately."""
        custom_baselines = [
            {
                "case_id": "TICKET-2026-NODEJS-01",
                "name": "Node.js October 2026 Emergency Patch",
                "baseline_lead_time_hours": 40.0,
                "evidence": "Jira ticket SEC-2026-890",
            },
            {
                "case_id": "TICKET-2026-NGINX-02",
                "name": "Nginx HTTP/2 Rapid Reset Manual Patch",
                "baseline_lead_time_hours": 60.0,
                "evidence": "Incident post-mortem doc #12",
            },
        ]

        metrics = calculate_case_metrics(
            t_minus_1_announced="2026-10-20T10:00:00Z",
            t0_detected="2026-10-20T11:00:00Z",
            t1_triaged="2026-10-20T12:00:00Z",
            t2_dispatched="2026-10-20T14:00:00Z",
            t3_attested="2026-10-21T10:00:00Z",
            user_baselines=custom_baselines,
        )

        # Baseline average: (40.0 + 60.0) / 2 = 50.0 hours
        # Total lead time: 24.0 hours -> Saved: 26.0 hours (52.0%)
        self.assertEqual(metrics["baseline_average_hours"], 50.0)
        self.assertEqual(metrics["baseline_count"], 2)
        self.assertEqual(metrics["lead_time_saved_hours"], 26.0)
        self.assertEqual(metrics["reduction_percentage"], 52.0)

    def test_load_user_baselines_file(self):
        """Verify loading user baselines from local json storage safely."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            f = Path(tmp_dir) / "baselines.json"
            f.write_text(json.dumps([{"baseline_lead_time_hours": 48.0}]), encoding="utf-8")
            loaded = load_user_baselines(str(f))
            self.assertEqual(len(loaded), 1)

            # Missing file returns empty list
            self.assertEqual(load_user_baselines(str(Path(tmp_dir) / "nonexistent.json")), [])

    def test_off_hours_detection_jst(self):
        """Verify off-hours detection for weekday business hours vs nights/weekends in JST."""
        # 1. Weekday Business Hours: Wednesday 14:00 JST (05:00 UTC) -> Not off-hours
        dt_work = datetime(2026, 10, 21, 5, 0, tzinfo=timezone.utc)
        self.assertFalse(is_off_hours_jst(dt_work))

        # 2. Weekday Night: Wednesday 22:00 JST (13:00 UTC) -> Off-hours
        dt_night = datetime(2026, 10, 21, 13, 0, tzinfo=timezone.utc)
        self.assertTrue(is_off_hours_jst(dt_night))

        # 3. Weekday Early Morning: Wednesday 06:00 JST (Tuesday 21:00 UTC) -> Off-hours
        dt_morning = datetime(2026, 10, 20, 21, 0, tzinfo=timezone.utc)
        self.assertTrue(is_off_hours_jst(dt_morning))

        # 4. Weekend: Saturday 14:00 JST (05:00 UTC) -> Off-hours
        dt_weekend = datetime(2026, 10, 24, 5, 0, tzinfo=timezone.utc)
        self.assertTrue(is_off_hours_jst(dt_weekend))


if __name__ == "__main__":
    unittest.main()
