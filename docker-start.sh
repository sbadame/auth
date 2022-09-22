#!/bin/sh

# Remove the node on exit.
trap '/app/tailscale logout' INT

/app/tailscaled --tun=userspace-networking --outbound-http-proxy-listen='localhost:1055' &

until /app/tailscale up --authkey=${TAILSCALE_AUTHKEY} --hostname=auth-app
do
    sleep 0.1
done
echo Tailscale started

HTTP_PROXY=http://localhost:1055/ /app/auth \
  -routingConfig="${ROUTING_CONFIG}" \
  -domainConfig="${DOMAIN_CONFIG}"

