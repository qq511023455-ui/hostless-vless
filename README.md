# VLESS over WebSocket for Hostless (free App tier)
#
# Hostless Apps are served over HTTPS only, so raw TCP VLESS cannot pass
# the proxy. This app speaks VLESS over WebSocket on path /vless, with
# TLS terminated by Hostless. Pure Python stdlib, no dependencies.
#
# Deploy: Create App in Hostless, connect this GitHub repo, build Docker.
# Hostless sets $PORT (default 8000); the app binds 0.0.0.0:$PORT.
# Set env var VLESS_UUID in the Hostless dashboard (never commit it).
# GET / returns 200 "ok" for health checks.
#
# Client link (fill in your app name and UUID):
# vless://<UUID>@<app>.hostless.app:443?path=%2Fvless&type=ws&security=tls&sni=<app>.hostless.app#Hostless
