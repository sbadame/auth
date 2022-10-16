#!/bin/sh

go build -o bin/auth cmd/auth/main.go || exit 1
gcloud run deploy auth --source=. --region=us-east1
