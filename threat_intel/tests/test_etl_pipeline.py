from django.test import TestCase
from unittest.mock import patch
from django.core.management import call_command
from threat_intel.models import Vulnerability

class ETLPipelineTest(TestCase):
    
    @patch('threat_intel.management.commands.extract_cves.requests.get')
    def test_extraction_command_success(self, mock_get):
        """Test that the ETL command correctly parses a valid API response."""
        
        # fake api response
        mock_response = mock_get.return_value
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-9999",
                        "published": "2026-05-29T00:00:00.000",
                        "lastModified": "2026-05-29T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "A critical test vulnerability."}],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}
                                }
                            ]
                        }
                    }
                }
            ]
        }

        call_command('extract_cves')

        self.assertTrue(mock_get.called)
        self.assertEqual(Vulnerability.objects.count(), 1)
        
        vuln = Vulnerability.objects.get(cve_id="CVE-2026-9999")
        self.assertEqual(vuln.base_score, 10.0)
        self.assertEqual(vuln.severity, "CRITICAL")
        self.assertEqual(vuln.description, "A critical test vulnerability.")