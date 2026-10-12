import os, tempfile, unittest
from app import create_app


class AppTests(unittest.TestCase):
    def setUp(self):
        os.environ.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
        self.c = create_app(os.path.join(tempfile.mkdtemp(), "t.db")).test_client()

    def scan(self, u, mode="individual"):
        return self.c.post("/api/scan", json={"url": u, "mode": mode})

    def test_clean_url_is_low(self):
        r = self.scan("https://www.wikipedia.org")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.json["level"], "Low")

    def test_invalid_urls_rejected(self):
        for u in ["", "javascript:alert(1)", "ftp://a.com", "not a url", "localhost", None]:
            self.assertEqual(self.scan(u).status_code, 400, u)

    def test_suspicious_url_is_high(self):
        r = self.scan("http://paypal-secure-login.verify-account.xyz/signin")
        self.assertEqual(r.json["level"], "High")
        self.assertTrue(any(f["id"] == "brand" for f in r.json["findings"]))

    def test_no_fake_threat_intel(self):
        self.assertEqual(self.scan("https://example.com").json["intel"]["status"], "not_configured")

    def test_history_stats_bulk_and_detail(self):
        self.scan("http://192.168.0.1:8080/login", "company")
        b = self.c.post("/api/scan/bulk", json={"urls": ["https://example.com", "bad url"]})
        self.assertEqual(len(b.json["results"]), 2)
        self.assertEqual(len(self.c.get("/api/history?mode=company").json["scans"]), 2)
        self.assertEqual(self.c.get("/api/stats?mode=company").json["total"], 2)
        sid = self.c.get("/api/history").json["scans"][0]["id"]
        self.assertEqual(self.c.get(f"/api/scan/{sid}").status_code, 200)
        self.assertEqual(self.c.get("/api/scan/9999").status_code, 404)

    def test_frontend_served(self):
        self.assertIn(b"ShieldScan", self.c.get("/").data)


if __name__ == "__main__":
    unittest.main()
