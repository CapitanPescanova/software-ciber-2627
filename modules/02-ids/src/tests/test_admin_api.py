import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))

from util.health import app


class AdminApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_localhost_can_list_and_disable_rules_without_token(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IDS_ADMIN_TOKEN", None)
            rules_response = self.client.get("/admin/rules")
            disable_response = self.client.post(
                "/admin/rules/P004/disable",
                json={"rule_id": "P004"},
            )

        self.assertEqual(rules_response.status_code, 200)
        self.assertEqual(rules_response.get_json()["rules"], ["P004", "P005"])
        self.assertEqual(disable_response.status_code, 200)

    def test_valid_token_is_required_when_configured(self):
        with patch.dict(os.environ, {"IDS_ADMIN_TOKEN": "secret-token"}):
            missing = self.client.get("/admin/rules")
            invalid = self.client.get(
                "/admin/rules",
                headers={"Authorization": "Bearer wrong-token"},
            )
            valid = self.client.get(
                "/admin/rules",
                headers={"Authorization": "Bearer secret-token"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(valid.status_code, 200)

    def test_remote_admin_request_is_forbidden(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IDS_ADMIN_TOKEN", None)
            response = self.client.get(
                "/admin/rules",
                environ_base={"REMOTE_ADDR": "192.0.2.10"},
            )

        self.assertEqual(response.status_code, 403)

    def test_unknown_rule_is_rejected(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IDS_ADMIN_TOKEN", None)
            response = self.client.post(
                "/admin/rules/P999/disable",
                json={"rule_id": "P999"},
            )

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
