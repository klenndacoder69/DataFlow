from django.test import TestCase
from django.db.utils import IntegrityError
from threat_intel.models import Vulnerability
from datetime import datetime, timezone

class VulnerabilityModelTest(TestCase):
    def setUp(self):
        # This runs before every test to set up baseline data
        self.valid_date = datetime(2026, 1, 1, tzinfo=timezone.utc)
        
    def test_create_valid_vulnerability(self):
        """Test that a standard, valid CVE saves correctly."""
        vuln = Vulnerability.objects.create(
            cve_id="CVE-2026-0001",
            description="A test privilege escalation vulnerability.",
            base_score=9.8,
            severity="CRITICAL",
            published_date=self.valid_date,
            last_modified_date=self.valid_date
        )
        self.assertEqual(vuln.cve_id, "CVE-2026-0001")
        self.assertEqual(vuln.severity, "CRITICAL")
        
    def test_unique_cve_id_enforcement(self):
        """Test that the database rejects duplicate CVE IDs."""
        Vulnerability.objects.create(
            cve_id="CVE-2026-0002",
            description="First entry",
            published_date=self.valid_date,
            last_modified_date=self.valid_date
        )
        
        # We expect the database to throw an IntegrityError if we reuse the ID
        with self.assertRaises(IntegrityError):
            Vulnerability.objects.create(
                cve_id="CVE-2026-0002",
                description="Duplicate entry",
                published_date=self.valid_date,
                last_modified_date=self.valid_date
            )