#!/bin/sh

/app/tailscaled --tun=userspace-networking --outbound-http-proxy-listen='localhost:1055' &

until /app/tailscale up --authkey=${TAILSCALE_AUTHKEY} --hostname=auth-app
do
    sleep 0.1
done
echo Tailscale started

HTTP_PROXY=http://localhost:1055/ /app/auth \
  -domainConfig="${DOMAIN_CONFIG}" \
  -routingConfig="${ROUTING_CONFIG}"
