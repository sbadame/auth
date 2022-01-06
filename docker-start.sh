#!/bin/sh

/app/tailscaled --tun=userspace-networking --socks5-server=localhost:1055 &
# /app/tailscaled --tun=userspace-networking --outbound-http-proxy-listen=localhost:1055 &
until /app/tailscale up --authkey=${TAILSCALE_AUTHKEY} --hostname=auth-app
do
    sleep 0.1
done

echo Tailscale started

export HTTP_PROXY=socks5://localhost:1055

/app/auth \
  -domainConfig="${DOMAIN_CONFIG}" \
  -routingConfig="${ROUTING_CONFIG}"
