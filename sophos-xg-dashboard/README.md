# Sophos XG/SFOS Dashboard Add-on

A Home Assistant add-on that displays Sophos Firewall / SFOS XML API information through Home Assistant Ingress.

## First supported views

- connection/API status
- firewall rules
- NAT rules
- raw counts and error diagnostics without exposing credentials

## Configuration

```yaml
sophos_host: https://10.17.1.1:4444
verify_ssl: false
username: api-user
password: your-secret-password
request_timeout: 15
refresh_interval: 60
```

## Notes

The Sophos XML API can differ between firmware versions. If an endpoint returns an XML status/error, the dashboard will show a safe error message and keep running.
