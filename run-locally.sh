#!/bin/bash

go build test/test_server.go && \
  PORT=8092 ./test_server &

go fmt && \
go build && \
PORT=8091 ./auth \
 -routingConfig='/test -> http://localhost:8092, /timeline -> http://100.103.175.63:8000'
# -domainConfig='{
#   "clientID":"477755167294-4lhig4thi64krcd8oj5jgtncklccgeef.apps.googleusercontent.com",
#   "cookieName":"id_token",
#   "loginURL": "http://localhost:8091/login?target=",
#   "allowedusers":["foo@bar.com"],
#   "cookiedomain":"raspberrypi"
# }' \

