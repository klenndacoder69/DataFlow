# DataFlow

An ETL pipeline that ingests CVE data from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), persists it to PostgreSQL, and exposes it through the Django admin interface.

## Stack

| Layer | Technology |
|---|---|
| Framework | Django 6 |
| Database | PostgreSQL 15 (Docker) |
| ETL | Custom Django management command |
| Data source | NVD REST API v2.0 |
| Testing | Django `TestCase` + `unittest.mock` |
| Environment | `python-dotenv` |

## Architecture

```
NVD API  ──►  extract_cves  ──►  PostgreSQL  ──►  Django Admin
              (management         (Vulnerability
               command)            model)
```

The `extract_cves` command fetches the last 7 days of published CVEs in paginated chunks of 100, handles rate limiting (HTTP 429), normalises CVSS v2/v3.0/v3.1 scores, and upserts records via `update_or_create`.

## Setup

```bash
# 1. Start the database
docker compose up -d

# 2. Create and activate virtual environment
python -m venv .venv && source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env   # then fill in DB credentials

# 5. Apply migrations
python manage.py migrate

# 6. Run the ETL pipeline
python manage.py extract_cves

# 7. (Optional) Access admin UI
python manage.py createsuperuser
python manage.py runserver
# → http://127.0.0.1:8000/admin
```

## Tests

```bash
python manage.py test threat_intel
```

Covers model integrity constraints (unique CVE IDs) and ETL command behaviour via mocked HTTP responses.
