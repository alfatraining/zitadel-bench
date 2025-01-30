#!/usr/bin/env sh

set -euo pipefail

cd /terraform
terraform init -upgrade -force-copy -input=false # args make terraform suppress prompts
terraform plan
terraform apply -auto-approve
