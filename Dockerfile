FROM golang:1.17-alpine3.13 as builder
WORKDIR /app
COPY . ./
ENV CGO_ENABLED=0
RUN go build

# From https://tailscale.com/kb/1108/cloudrun/
FROM alpine:3.12 as tailscale
WORKDIR /app
COPY . ./
ENV TSFILE=tailscale_1.18.1_amd64.tgz
# ENV TSFILE=tailscale_1.18.1_arm.tgz
RUN wget https://pkgs.tailscale.com/stable/${TSFILE} && tar xzf ${TSFILE} --strip-components=1
COPY . ./

# FROM alpine:3.11
# RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*

FROM debian:latest

# Copy binary to production image
COPY --from=builder /app/auth /app/auth
COPY --from=builder /app/docker-start.sh /app/docker-start.sh
COPY --from=tailscale /app/tailscaled /app/tailscaled
COPY --from=tailscale /app/tailscale /app/tailscale
RUN mkdir -p /var/run/tailscale /var/cache/tailscale /var/lib/tailscale

# Get the certs needed to validate google jwts
# https://github.com/debuerreotype/docker-debian-artifacts/issues/15#issuecomment-634423712
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates

 RUN update-ca-certificates

# Run tailscale + the auth server with the proper environment variables.
CMD ["/app/docker-start.sh"]
