#!/bin/sh

go build . || exit 1
gcloud run deploy auth --source=. --region=us-east1
