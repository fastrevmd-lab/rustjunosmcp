# Prometheus metrics

Prometheus metrics are opt-in on the streamable-HTTP servers.

| Binary | Flag | Environment variable | Default target |
| --- | --- | --- | --- |
| rust-junosmcp | --enable-metrics | JMCP_ENABLE_METRICS | 127.0.0.1:30030 |
| rust-srxmcp | --enable-metrics | JMCP_SRX_ENABLE_METRICS | 127.0.0.1:30032 |

When disabled, GET /metrics returns 404 Not Found because the route is not
registered. Junos refuses --enable-metrics with --transport stdio.

## Security

GET /metrics is intentionally unauthenticated and bypasses bearer-token
authentication, rmcp Host validation, and MCP resource-limit middleware. It
shares the configured HTTP/TLS listener. Bind to loopback or restrict the
endpoint with a host firewall, reverse proxy, or equivalent network control.
Metrics contain aggregate bounded labels only; they never contain token,
caller, router, session, correlation, or error identifiers.

## Scrape configuration

```yaml
scrape_configs:
  - job_name: rust-junosmcp
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:30030"]

  - job_name: rust-srxmcp
    metrics_path: /metrics
    static_configs:
      - targets: ["127.0.0.1:30032"]
```

For a listener using the server's TLS certificate:

```yaml
scrape_configs:
  - job_name: rust-junosmcp-tls
    scheme: https
    metrics_path: /metrics
    tls_config:
      ca_file: /etc/prometheus/jmcp-ca.pem
      server_name: jmcp.example.net
    static_configs:
      - targets: ["jmcp.example.net:30030"]
```

No Authorization header is required for the metrics route.

## Metric names

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| junosmcp_active_sessions | gauge | server | Sessions currently tracked by the HTTP session manager |
| junosmcp_limit_hits_total | counter | server, limit, event | HTTP rejections and manager-level global session-cap hits |
| junosmcp_tool_duration_seconds | histogram | server, tool, result | Tool-handler elapsed seconds |
| junosmcp_sessions_reaped_total | counter | server, reason | Sessions removed by the idle/lifetime reaper |

Fixed values:

- server: junos or srx
- limit: request_body, token_rate, global_concurrency, token_concurrency,
  router_concurrency, session_cap, or token_session_cap
- event: request_rejected or session_registration_rejected
- result: ok, error, denied, or unsettled
- reason: idle or lifetime

A concurrent initialize that reaches the manager race backstop records both
`limit="session_cap", event="session_registration_rejected"` for the atomic
manager decision and `limit="session_cap", event="request_rejected"` for the
503 returned to the client. An initialize rejected by the middleware fast path
records only the client-facing `request_rejected` event.

Counter and histogram label series appear after their first event. The active
session gauge is initialized to zero. The tool histogram has buckets from
0.01 seconds through 1800 seconds.

Queue time is not exported because request-rate and concurrency gates reject
immediately instead of queueing (`429` and `503`, respectively).

## Example PromQL

Active sessions:

```promql
junosmcp_active_sessions
```

Rejection rate by server and limit:

```promql
sum by (server, limit) (
  rate(junosmcp_limit_hits_total{event="request_rejected"}[5m])
)
```

95th-percentile tool duration:

```promql
histogram_quantile(
  0.95,
  sum by (le, server, tool) (
    rate(junosmcp_tool_duration_seconds_bucket[5m])
  )
)
```

Tool error rate:

```promql
sum by (server, tool) (
  rate(junosmcp_tool_duration_seconds_count{result="error"}[5m])
)
```

Session reaper rate:

```promql
sum by (server, reason) (
  rate(junosmcp_sessions_reaped_total[5m])
)
```
