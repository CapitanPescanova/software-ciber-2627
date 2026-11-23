import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.append(str(Path(__file__).resolve().parents[1]))

from patterns.brute_force import BruteForce
from patterns.endpoint_scan import EndpointScan
from util.siem_publisher import publish_and_queue, retry_pending


class FakeResponse:
    def __init__(self, status_code=200, event_id=None, text=""):
        self.status_code = status_code
        self.text = text
        self._event_id = event_id

    def json(self):
        if self._event_id is None:
            return {}
        return {"event_id": self._event_id}


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append(copy.deepcopy(json))
        if not self.responses:
            raise RuntimeError("No fake response configured")
        return self.responses.pop(0)


class TimeoutSession:
    def __init__(self):
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append(copy.deepcopy(json))
        raise requests.Timeout("SIEM timeout")


class SiemPublisherTests(unittest.TestCase):
    def setUp(self):
        self.event = {
            "event_id": "IDS-P005-203.0.113.9-20261123T105900Z",
            "timestamp": "2026-11-23T11:00:20Z",
            "source": "ids",
            "event_type": "endpoint_scan",
            "severity": "high",
            "title": "Posible escaneo de endpoints",
            "description": "Prueba",
            "details": {"rule_id": "P005", "target_ips": ["10.0.0.1"]},
        }

    def test_409_is_permanent_reject_and_not_queued(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(
                    status_code=409,
                    text='{"code":"EVENT_ID_CONFLICT","message":"duplicate event"}',
                )
            ])

            with self.assertLogs("util.siem_publisher", level="ERROR") as captured:
                sent = publish_and_queue(
                    self.event,
                    siem_url="http://siem/events",
                    session=session,
                    pending_path=pending_path,
                    retries=0,
                    retry_delay=0,
                )

            self.assertFalse(sent)
            self.assertEqual([], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))
            self.assertIn("Rechazo definitivo", "\n".join(captured.output))
            self.assertIn("EVENT_ID_CONFLICT", "\n".join(captured.output))

    def test_503_is_queued_with_original_event(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(status_code=503, text="not ready")
            ])

            sent = publish_and_queue(
                self.event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
            )

            self.assertFalse(sent)
            pending = __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            )
            self.assertEqual([self.event], pending)

    def test_timeout_is_queued_with_original_event(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = TimeoutSession()

            sent = publish_and_queue(
                self.event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
            )

            self.assertFalse(sent)
            pending = __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            )
            self.assertEqual([self.event], pending)
            self.assertEqual([self.event], session.calls)

    def test_200_is_sent_and_removed_from_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(status_code=200, event_id=self.event["event_id"])
            ])

            sent = publish_and_queue(
                self.event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
            )

            self.assertTrue(sent)
            self.assertEqual([], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))
    def test_p005_is_common_schema_compatible(self):
        rule = EndpointScan(threshold="3", window="60")
        events = [
            {
                "timestamp": "Nov 20 10:00:00",
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.1",
                "destination_port": 22,
            },
            {
                "timestamp": "Nov 20 10:00:10",
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.2",
                "destination_port": 80,
            },
            {
                "timestamp": "Nov 20 10:00:20",
                "source_ip": "203.0.113.9",
                "destination_ip": "10.0.0.3",
                "destination_port": 443,
            },
        ]

        with patch("patterns.endpoint_scan.datetime") as mocked_datetime:
            mocked_datetime.now.return_value.year = 2026
            mocked_datetime.strptime.side_effect = lambda value, fmt: __import__(
                "datetime"
            ).datetime.strptime(value, fmt)
            detections = rule.run(events)

        self.assertEqual(len(detections), 1)
        event = detections[0]
        self.assertEqual(set(event), {
            "event_id", "timestamp", "source", "event_type", "severity",
            "title", "description", "details",
        })
        self.assertEqual(event["source"], "ids")
        self.assertEqual(event["event_type"], "endpoint_scan")
        self.assertIn(event["severity"], {"medium", "high"})
        self.assertIn(event["details"]["rule_id"], {"P005"})
        self.assertTrue(event["event_id"].startswith("IDS-P005-"))
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_p004_is_common_schema_compatible(self):
        rule = BruteForce(threshold="3", window="60", usernames="2")
        events = [
            {
                "timestamp": "Nov 20 10:00:00",
                "event_type": "failed_login",
                "source_ip": "203.0.113.9",
                "username": "root",
                "service": "ssh",
            },
            {
                "timestamp": "Nov 20 10:00:10",
                "event_type": "failed_login",
                "source_ip": "203.0.113.9",
                "username": "admin",
                "service": "ssh",
            },
            {
                "timestamp": "Nov 20 10:00:20",
                "event_type": "failed_login",
                "source_ip": "203.0.113.9",
                "username": "admin",
                "service": "ssh",
            },
        ]

        with patch("patterns.brute_force.datetime") as mocked_datetime:
            mocked_datetime.now.return_value.year = 2026
            mocked_datetime.strptime.side_effect = lambda value, fmt: __import__(
                "datetime"
            ).datetime.strptime(value, fmt)
            detections = rule.run(events)

        self.assertEqual(len(detections), 1)
        event = detections[0]
        self.assertEqual(event["source"], "ids")
        self.assertEqual(event["event_type"], "brute_force")
        self.assertIn(event["severity"], {"medium", "high", "critical"})
        self.assertEqual(event["details"]["rule_id"], "P004")
        self.assertTrue(event["event_id"].startswith("IDS-P004-"))
        self.assertTrue(event["timestamp"].endswith("Z"))

    def test_retry_preserves_original_event_exactly(self):
        event = {
            "event_id": "IDS-P005-203.0.113.9-20261123T105900Z",
            "timestamp": "2026-11-23T11:00:20Z",
            "source": "ids",
            "event_type": "endpoint_scan",
            "severity": "high",
            "title": "Posible escaneo de endpoints",
            "description": "Prueba",
            "details": {"rule_id": "P005", "target_ips": ["10.0.0.1"]},
        }

        with tempfile.TemporaryDirectory() as directory:
            pending_path = Path(directory) / "pending_events.json"
            session = FakeSession([
                FakeResponse(status_code=503, text="not ready"),
                FakeResponse(status_code=200, event_id=event["event_id"]),
            ])

            original = copy.deepcopy(event)
            self.assertFalse(publish_and_queue(
                event,
                siem_url="http://siem/events",
                session=session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
            ))
            self.assertEqual(event, original)

            retry_session = FakeSession([
                FakeResponse(status_code=200, event_id=event["event_id"])
            ])
            retry_pending(
                siem_url="http://siem/events",
                session=retry_session,
                pending_path=pending_path,
                retries=0,
                retry_delay=0,
            )

            self.assertEqual(session.calls[0], original)
            self.assertEqual(retry_session.calls[0], original)
            self.assertEqual([], __import__("json").loads(
                pending_path.read_text(encoding="utf-8")
            ))


if __name__ == "__main__":
    unittest.main()
