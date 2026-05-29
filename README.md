# DataFlow

An ETL pipeline that ingests CVE data from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities), persists it to PostgreSQL, and exposes it through the Django admin interface. Served in production via Gunicorn + Nginx.

## Stack

| Layer | Technology |
|---|---|
| Framework | Django 6 |
| Database | PostgreSQL 15 (Docker) |
| ETL | Custom Django management command |
| Data source | NVD REST API v2.0 |
| Application server | Gunicorn (3 workers) |
| Reverse proxy | Nginx |
| Testing | Django `TestCase` + `unittest.mock` |
| Environment | `python-dotenv` |

## Architecture

```
NVD API  ──►  extract_cves  ──►  PostgreSQL
              (management
               command)               │
                                      ▼
Client  ──►  Nginx  ──►  Gunicorn  ──►  Django (Admin UI)
             (port 80,    (127.0.0.1
              static       :8000)
              files)
```

- **Nginx** handles incoming HTTP traffic and serves `staticfiles/` directly
- **Gunicorn** runs the Django WSGI app on localhost, proxied from Nginx
- The **ETL command** runs independently, pulling and upserting CVE records on demand

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
```

## Production Deployment (Gunicorn + Nginx)

```bash
# Collect static files for Nginx to serve
python manage.py collectstatic

# Start Gunicorn
gunicorn core.wsgi:application --bind 127.0.0.1:8000 --workers 3
```

Nginx is configured to proxy requests to Gunicorn and serve `staticfiles/` directly:

```nginx
server {
    listen 80;

    location /static/ {
        alias /home/swapols/projects/DataFlow/staticfiles/;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Tests

```bash
python manage.py test threat_intel
```

Covers model integrity constraints (unique CVE IDs) and ETL command behaviour via mocked HTTP responses.
