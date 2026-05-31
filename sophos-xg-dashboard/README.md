# Sophos XG/SFOS Dashboard Add-on

A Home Assistant add-on that displays Sophos Firewall / SFOS XML API information through Home Assistant Ingress.

## First supported views

- connection/API status
- Home Assistant style statistic cards for firewall/NAT totals, enabled/disabled rules, and logged firewall rules
- breakdown panels for firewall actions, source zones, and NAT translation types
- searchable firewall and NAT rule tables
- raw counts and error diagnostics without exposing credentials

## Configuration

```yaml
sophos_host: https://192.0.2.10:4444
verify_ssl: false
username: api-user
password: your-secret-password
request_timeout: 30
refresh_interval: 60
```

## Notes

The Sophos XML API can differ between firmware versions. If an endpoint returns an XML status/error, the dashboard will show a safe error message and keep running.
