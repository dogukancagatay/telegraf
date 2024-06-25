# OpenTelemetry HTTP Output Plugin

This plugin sends metrics to [OpenTelemetry](https://opentelemetry.io) servers
and agents via HTTP.

## Global configuration options <!-- @/docs/includes/plugin_config.md -->

In addition to the plugin-specific configuration settings, plugins support
additional global and plugin configuration settings. These settings are used to
modify metrics, tags, and field or create aliases and configure ordering, etc.
See the [CONFIGURATION.md][CONFIGURATION.md] for more details.

[CONFIGURATION.md]: ../../../docs/CONFIGURATION.md#plugins

## Secret-store support

This plugin supports secrets from secret-stores for the `username`, `password`, `bearer_token` and `headers` option.
See the [secret-store documentation][SECRETSTORE] for more details on how
to use them.

[SECRETSTORE]: ../../../docs/CONFIGURATION.md#secret-store-secrets

## Configuration

```toml @sample.conf
# A plugin that can transmit metrics over HTTP
[[outputs.http]]
## URL is the address to send OpenTelemetry metrics to
## scheme must be "http" or "https"
# url = "http://localhost:4318/v1/metrics"

## Timeout for HTTP message
# timeout = "5s"

## Override the default (gzip) compression used to send data.
## Supports: "gzip", "none"
# compression = "gzip"

## Optional TLS Config.
##
## Root certificates for verifying server certificates encoded in PEM format.
# tls_ca = "/etc/telegraf/ca.pem"
## The public and private key pairs for the client encoded in PEM format.
## May contain intermediate certificates.
# tls_cert = "/etc/telegraf/cert.pem"
# tls_key = "/etc/telegraf/key.pem"
## Use TLS, but skip TLS chain and host verification.
# insecure_skip_verify = false
## Send the specified TLS server name via SNI.
# tls_server_name = "foo.example.com"

## HTTP Basic Auth credentials
# username = "username"
# password = "pa$$word"

## HTTP Bearer token authentication
# bearer_token = "XYZ"

## HTTP Proxy support
# use_system_proxy = false
# http_proxy_url = ""

## NOTE: Due to the way TOML is parsed, tables must be at the END of the
## plugin definition, otherwise additional config options are read as part of
## the table

## Additional HTTP request headers
# [outputs.opentelemetry_http.headers]
#    Authorization = "Token <token>"
```
