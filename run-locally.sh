#!/bin/bash

go fmt && \
go build && \
PORT=8091 ./auth \
 -domainConfig='{
   "clientID":"477755167294-4lhig4thi64krcd8oj5jgtncklccgeef.apps.googleusercontent.com",
   "cookieName":"id_token",
   "loginURL": "http://raspberrypi:8091/login?target=",
   "allowedusers":["foo@bar.com"],
   "cookiedomain":"raspberrypi"
}'

