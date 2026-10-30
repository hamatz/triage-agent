"""Tests for Lifecycle Metrics and MTTR Tracking (v0.3.1 / ADR-019)."""

from datetime import datetime, timezone, timedelta
import unittest

from triage_agent.tools.lifecycle_metrics import (
    AVERAGE_BASELINE_HOURS,
    HISTORICAL_BASELINES,
    calculate_case_metrics,
    is_off_hours_jst,
)


class TestLifecycleMetrics(unittest.TestCase):
    """Test suite for lifecycle metrics, off-hours detection, and baseline comparison."""

    def test_historical_baselines_integrity(self):
        """Historical baselines must contain verifiable cases with valid URLs and positive lead times."""
        self.assertGreaterEqual(len(HISTORICAL_BASELINES), 3)
        for b in HISTORICAL_BASELINES:
            self.assertTrue(b["case_id"].startswith("BASE-"))
            self.assertIn("https://", b["source_url"])
            self.assertGreater(b["baseline_lead_time_hours"], 0.0)
        self.assertAlmostEqual(AVERAGE_BASELINE_HOURS, 74.9, places=1)

    def test_off_hours_detection_jst(self):
        """Verify off-hours detection for weekday business hours vs nights/weekends in JST."""
        jst = timezone(timedelta(hours=9))

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

    def test_calculate_case_metrics_end_to_end(self):
        """Verify end-to-end lead times from announcement T(-1) to attest T(3) and baseline reduction."""
        # Scenario: Announced 2026-10-20 10:00 UTC, Dispatched 14:00 UTC (4h), Attested 2026-10-21 10:00 UTC (20h turnaround)
        # Total lead time = 24.0 hours (Saved 50.9h vs 74.9h baseline)
        metrics = calculate_case_metrics(
            t_minus_1_announced="2026-10-20T10:00:00Z",
            t0_detected="2026-10-20T11:00:00Z",
            t1_triaged="2026-10-20T12:00:00Z",
            t2_dispatched="2026-10-20T14:00:00Z",
            t3_attested="2026-10-21T10:00:00Z",
        )

        self.assertEqual(metrics["lead_time_announce_to_dispatch_hours"], 4.0)
        self.assertEqual(metrics["turnaround_dispatch_to_attest_hours"], 20.0)
        self.assertEqual(metrics["total_lead_time_hours"], 24.0)
        self.assertEqual(metrics["baseline_average_hours"], 74.9)
        self.assertAlmostEqual(metrics["lead_time_saved_hours"], 50.9, places=1)
        self.assertGreater(metrics["reduction_percentage"], 65.0)


if __name__ == "__main__":
    unittest.main()
