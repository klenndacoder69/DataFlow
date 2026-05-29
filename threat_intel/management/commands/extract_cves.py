import time
import requests
from datetime import datetime, timedelta, timezone
from django.core.management.base import BaseCommand
from threat_intel.models import Vulnerability

class Command(BaseCommand):
    help = "Extracts CVEs from NVD and stores to db (PostgreSQL)"

    # goal is to get the data, sort and compile the data to variables, and push it into the db
    def handle(self, *args, **kwargs):
        self.stdout.write("Starting CVE extraction...")

        now = datetime.now(timezone.utc)
        start_date = now - timedelta(days=7)

        end_str = now.strftime('%Y-%m-%dT%H:%M:%S.000')
        start_str = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')

        start_index = 0
        results_per_page = 100
        total_results = 1

        RATE_LIMIT_DELAY = 6
        while start_index < total_results:
            self.stdout.write(f"Fetching chunk: startIndex={start_index}...")
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={start_str}&pubEndDate={end_str}&resultsPerPage={results_per_page}&startIndex={start_index}" 
            try:
                response = requests.get(url, timeout=15)

                if response.status_code == 429:
                    self.stderr.write("ERR: 429 (rate limit).")
                    time.sleep(30)
                    continue
                response.raise_for_status()
                data = response.json()
            except requests.RequestException as e:
                self.stderr.write(f"Failed at offset {start_index} error: {e}")
                return
            
            total_results = data.get('totalResults', 0)
            vulnerabilities = data.get('vulnerabilities',[])

            self.stdout.write(f"Total records in upstream window: {total_results}")

            for item in vulnerabilities:

                cve_data = item.get('cve',{})
                cve_id = cve_data.get('id')


                description = "No description provided."
                for desc in cve_data.get('descriptions',[]):
                    lang = desc.get('lang', '').lower()
                    if lang.startswith('en'):
                        description = desc.get('value')
                        break
                published_date = cve_data.get('published')
                last_modified_date = cve_data.get('lastModified')

                base_score = None
                severity = None

                # cvss is optional, we still try to get it when necessary
                metrics = cve_data.get('metrics',{})

                # to account for other versions
                if 'cvssMetricV31' in metrics:
                    metric_data = metrics['cvssMetricV31'][0]
                    base_score = metric_data.get('cvssData', {}).get('baseScore')
                    severity = metric_data.get('cvssData', {}).get('baseSeverity')
                    
                elif 'cvssMetricV30' in metrics:
                    metric_data = metrics['cvssMetricV30'][0]
                    base_score = metric_data.get('cvssData', {}).get('baseScore')
                    severity = metric_data.get('cvssData', {}).get('baseSeverity')
                    
                elif 'cvssMetricV2' in metrics:
                    metric_data = metrics['cvssMetricV2'][0]
                    base_score = metric_data.get('cvssData', {}).get('baseScore')
                    # In V2, baseSeverity is at the root of the metric_data, not inside cvssData
                    severity = metric_data.get('baseSeverity')            

                obj, created = Vulnerability.objects.update_or_create(
                    cve_id=cve_id,
                    defaults={
                        'description': description,
                        'base_score': base_score,
                        'severity': severity,
                        'published_date': published_date,
                        'last_modified_date': last_modified_date
                    }
                )

                action = "Created" if created else "Updated"
                self.stdout.write(f"{action}: {cve_id} (Score: {base_score})")

            start_index += results_per_page 
            if start_index < total_results:
                self.stdout.write(f"Sleeping for {RATE_LIMIT_DELAY}")
                time.sleep(RATE_LIMIT_DELAY)

        self.stdout.write(self.style.SUCCESS("Completed CVE extraction."))

