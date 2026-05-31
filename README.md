# Home Assistant Add-on: Sophos XG/SFOS Dashboard

Private Home Assistant add-on repository for a Sophos XG / Sophos Firewall (SFOS) dashboard.

The add-on talks to the local Sophos XML API and exposes a Home Assistant Ingress web UI with:

- firewall/API connectivity status
- firewall rules summary
- NAT rules summary
- basic service health endpoint
- structured JSON endpoints for future Home Assistant sensors/automations

> Status: initial scaffold. The XML parser is defensive and designed to be extended once real SFOS XML responses are available for the target firewall/firmware version.

## Add this repository to Home Assistant

1. Push this repository to GitHub.
2. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
3. Add the repository URL.
4. Install **Sophos XG/SFOS Dashboard**.

## Required Sophos setup

On the Sophos firewall:

1. Enable XML API access.
2. Create/use a low-privilege API user if possible.
3. Allow API access only from the Home Assistant host IP/subnet.
4. Use the firewall management URL, for example:

```text
https://10.17.1.1:4444
```

## Add-on options

```yaml
sophos_host: https://10.17.1.1:4444
verify_ssl: false
username: api-user
password: your-secret-password
request_timeout: 15
refresh_interval: 60
```

No real credentials belong in this repository.

## API endpoints

Inside the add-on/ingress:

- `GET /` — dashboard UI
- `GET /api/health` — local app health
- `GET /api/summary` — combined Sophos status/rules summary
- `GET /api/firewall-rules` — parsed firewall rules
- `GET /api/nat-rules` — parsed NAT rules

## Development

```bash
cd sophos-xg-dashboard
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export SOPHOS_HOST="https://10.17.1.1:4444"
export SOPHOS_USERNAME="api-user"
export SOPHOS_PASSWORD="secret"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Security notes

- Do not log XML payloads containing `<Password>`.
- Keep `verify_ssl: true` where possible; `false` is common in homelabs with self-signed certs.
- Keep the Sophos XML API allowlist narrow.
- Treat this add-on as management-plane software.
