#!/usr/bin/env bash
# Produce an offline Terraform plan and its JSON, with no route to AWS.
# - ambient AWS_* variables are unset
# - placeholder credentials are exported only for this process
# - every AWS endpoint points at a closed local port, so any API call fails locally
# - refresh is off and there is no backend or state
set -euo pipefail
cd "$(dirname "$0")/../terraform"

for var in $(env | awk -F= '/^AWS_/ {print $1}'); do unset "$var"; done
export AWS_ACCESS_KEY_ID="offline-placeholder"
export AWS_SECRET_ACCESS_KEY="offline-placeholder"
export AWS_EC2_METADATA_DISABLED=true
export AWS_ENDPOINT_URL="http://127.0.0.1:9"
export AWS_CONFIG_FILE=/dev/null
export AWS_SHARED_CREDENTIALS_FILE=/dev/null

mkdir -p ../build
terraform init -backend=false -input=false >/dev/null
terraform plan -input=false -lock=false -refresh=false -out=../build/offline.tfplan
terraform show -json ../build/offline.tfplan > ../build/plan.json
echo "wrote build/plan.json"
