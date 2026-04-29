"""
Tests for the vulnerable application.

Note: These tests are minimal and just verify basic functionality.
They do NOT test for security - that's what Snyk is for!
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.vulnerable_app import app, init_db


class TestVulnerableApp(unittest.TestCase):
    """Test cases for the vulnerable Flask application."""

    @classmethod
    def setUpClass(cls):
        """Set up test fixtures."""
        app.config["TESTING"] = True
        cls.client = app.test_client()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            os.chdir(tmpdir)
            init_db()

    def test_get_user_returns_404_for_missing_user(self):
        """Test that get_user returns 404 for non-existent user."""
        response = self.client.get("/user/99999")
        self.assertEqual(response.status_code, 404)

    def test_search_returns_json(self):
        """Test that search endpoint returns JSON."""
        response = self.client.get("/search?name=test")
        self.assertEqual(response.content_type, "application/json")

    def test_render_template_returns_html(self):
        """Test that render endpoint returns HTML."""
        response = self.client.get("/render?name=Test")
        self.assertIn(b"Hello Test!", response.data)

    def test_execute_requires_json(self):
        """Test that execute endpoint requires JSON body."""
        response = self.client.post(
            "/execute",
            data=json.dumps({"filename": "test.txt"}),
            content_type="application/json"
        )
        self.assertEqual(response.status_code, 200)

    def test_read_file_returns_404_for_missing_file(self):
        """Test that read-file returns 404 for non-existent file."""
        response = self.client.get("/read-file?filename=nonexistent.txt")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
