# Home Assistant Add-on: Sophos XG/SFOS Dashboard

Home Assistant add-on repository for a Sophos XG / Sophos Firewall (SFOS) dashboard.

<img width="1383" height="1339" alt="grafik" src="https://github.com/user-attachments/assets/a3e6aaa5-f7b8-4b00-9e27-7bd72dedcf3a" />


The add-on talks to the local Sophos XML API and exposes a Home Assistant Ingress web UI with:

- firewall/API connectivity status
- firewall rules summary
- NAT rules summary
- basic service health endpoint
- structured JSON endpoints for future Home Assistant sensors/automations

> Status: initial scaffold. The XML parser is defensive and designed to be extended once real SFOS XML responses are available for the target firewall/firmware version.

## Add this repository to Home Assistant

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Add the repository URL.
3. Install **Sophos XG/SFOS Dashboard**.

## Required Sophos setup

On the Sophos firewall:

1. Enable XML API access: **Backup & firmware → API → API configuration***
2. Create/use a low-privilege API user if possible (Read-Only is enough).
3. Allow API access only from the Home Assistant host IP/subnet.

## Add-on options

```yaml
sophos_host: https://192.0.2.10:4444
verify_ssl: false
username: api-user
password: your-secret-password
request_timeout: 30
refresh_interval: 60
```

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
export SOPHOS_HOST="https://192.0.2.10:4444"
export SOPHOS_USERNAME="api-user"
export SOPHOS_PASSWORD="secret"
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Security notes

- Do not log XML payloads containing `<Password>`.
- Keep `verify_ssl: true` where possible; `false` is common in homelabs with self-signed certs.
- Keep the Sophos XML API allowlist narrow.
- Treat this add-on as management-plane software.

## Star History

<a href="https://www.star-history.com/?repos=vmhomelab%2Fha-addon-sophos-xg-dashboard&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=vmhomelab/ha-addon-sophos-xg-dashboard&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=vmhomelab/ha-addon-sophos-xg-dashboard&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=vmhomelab/ha-addon-sophos-xg-dashboard&type=date&legend=top-left" />
 </picture>
</a>
