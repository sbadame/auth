#!/bin/bash

gofmt -w -s . || exit 'Error running gofmt.'

go build -o bin/test_server test/test_server.go && \
  PORT=8092 ./test_server &

go build -o bin/auth cmd/auth/main.go && \
PORT=8091 ./bin/auth \
 -routingConfig='/test -> http://localhost:8092, /timeline -> http://100.103.175.63:8000'
# -domainConfig='{
#   "clientID":"477755167294-4lhig4thi64krcd8oj5jgtncklccgeef.apps.googleusercontent.com",
#   "cookieName":"id_token",
#   "loginURL": "http://localhost:8091/login?target=",
#   "allowedusers":["foo@bar.com"],
#   "cookiedomain":"raspberrypi"
# }' \

