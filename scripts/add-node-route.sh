#!/usr/bin/env bash
#
# Add a TOPRF node to the API Gateway routing.
#
# Usage:  ./scripts/add-node-route.sh <node-id> <aws-region> <operator-ip>
# Example: ./scripts/add-node-route.sh 5 us-east-1 54.123.45.67
#
# What this does:
#   1. Requests *.ruonlabs.com wildcard cert in <region> (if one doesn't exist)
#   2. Creates an HTTP API Gateway in <region> with HTTP_PROXY to the operator IP
#   3. Attaches custom domain nodeN.ruonlabs.com with the regional cert
#   4. Creates Route53 alias record nodeN.ruonlabs.com -> API Gateway
#
# After running, the node is reachable at:
#   https://nodeN.ruonlabs.com/{health,attestation,partial-evaluate}
#
# Remove a node: ./scripts/remove-node-route.sh <node-id>

set -euo pipefail

DOMAIN="ruonlabs.com"
HOSTED_ZONE_ID="Z01227431UKG0UT7HK94V"
NODE_PORT="3001"

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <node-id> <aws-region> <operator-ip>" >&2
  exit 1
fi

NODE_ID="$1"
REGION="$2"
NODE_IP="$3"

if ! [[ "$NODE_ID" =~ ^[0-9]+$ ]]; then
  echo "Error: node-id must be numeric" >&2; exit 1
fi
if ! [[ "$NODE_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "Error: operator-ip must be a valid IPv4 address" >&2; exit 1
fi

NODE_DOMAIN="node${NODE_ID}.${DOMAIN}"
echo "==> Adding routing:"
echo "    Node:          ${NODE_ID} at ${NODE_IP} (region: ${REGION})"
echo "    Public URL:    https://${NODE_DOMAIN}"
echo

# ---- Step 1: Find or request wildcard cert in this region -----------------
echo "==> [1/5] Finding/requesting *.${DOMAIN} cert in ${REGION}"
CERT_ARN=$(aws acm list-certificates --region "$REGION" \
  --query "CertificateSummaryList[?DomainName=='${DOMAIN}'] | [?contains(SubjectAlternativeNameSummaries, \`*.${DOMAIN}\`)].CertificateArn | [0]" \
  --output text)
if [[ -z "$CERT_ARN" || "$CERT_ARN" == "None" ]]; then
  echo "    No wildcard cert found — requesting new one"
  CERT_ARN=$(aws acm request-certificate \
    --domain-name "$DOMAIN" \
    --subject-alternative-names "*.$DOMAIN" \
    --validation-method DNS \
    --region "$REGION" \
    --query 'CertificateArn' --output text)
  echo "    Requested: $CERT_ARN"
  sleep 5
  # The validation CNAME for this domain is always the same across regions/certs,
  # and should already exist in Route53 from earlier certs. Wait for ISSUED.
  echo "    Waiting for validation (existing CNAME should already be in Route53)..."
  for i in {1..30}; do
    STATUS=$(aws acm describe-certificate --certificate-arn "$CERT_ARN" --region "$REGION" --query 'Certificate.Status' --output text)
    if [[ "$STATUS" == "ISSUED" ]]; then break; fi
    sleep 10
  done
  if [[ "$STATUS" != "ISSUED" ]]; then
    echo "    Cert not issued after 5min — run describe-certificate to check validation CNAME" >&2
    exit 1
  fi
fi
echo "    Cert: $CERT_ARN"

# ---- Step 2: Create HTTP API Gateway -------------------------------------
echo "==> [2/5] Creating HTTP API in ${REGION}"
API_ID=$(aws apigatewayv2 create-api \
  --name "toprf-node-${NODE_ID}" \
  --protocol-type HTTP \
  --region "$REGION" \
  --description "TOPRF node ${NODE_ID} (${NODE_IP})" \
  --query 'ApiId' --output text)
echo "    API:   $API_ID"

# Integration
INT_ID=$(aws apigatewayv2 create-integration \
  --api-id "$API_ID" --region "$REGION" \
  --integration-type HTTP_PROXY --integration-method ANY \
  --integration-uri "http://${NODE_IP}:${NODE_PORT}/{proxy}" \
  --payload-format-version 1.0 \
  --query 'IntegrationId' --output text)

# Route (catch-all)
aws apigatewayv2 create-route --api-id "$API_ID" --region "$REGION" \
  --route-key 'ANY /{proxy+}' --target "integrations/${INT_ID}" --query 'RouteKey' --output text > /dev/null

# Stage with auto-deploy
aws apigatewayv2 create-stage --api-id "$API_ID" --region "$REGION" \
  --stage-name '$default' --auto-deploy --query 'StageName' --output text > /dev/null

# ---- Step 3: Custom domain + API mapping ---------------------------------
echo "==> [3/5] Creating custom domain ${NODE_DOMAIN}"
DOMAIN_RESULT=$(aws apigatewayv2 create-domain-name \
  --domain-name "$NODE_DOMAIN" --region "$REGION" \
  --domain-name-configurations "CertificateArn=${CERT_ARN},EndpointType=REGIONAL,SecurityPolicy=TLS_1_2" \
  --output json)
TARGET=$(echo "$DOMAIN_RESULT" | jq -r '.DomainNameConfigurations[0].ApiGatewayDomainName')
HZ=$(echo "$DOMAIN_RESULT" | jq -r '.DomainNameConfigurations[0].HostedZoneId')
echo "    Target: $TARGET"

aws apigatewayv2 create-api-mapping \
  --domain-name "$NODE_DOMAIN" --api-id "$API_ID" --stage '$default' --region "$REGION" \
  --query 'ApiMappingId' --output text > /dev/null

# ---- Step 4: Route53 alias record ----------------------------------------
echo "==> [4/5] Creating Route53 alias ${NODE_DOMAIN} -> API Gateway"
aws route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch "{
  \"Changes\": [{
    \"Action\": \"UPSERT\",
    \"ResourceRecordSet\": {
      \"Name\": \"${NODE_DOMAIN}\",
      \"Type\": \"A\",
      \"AliasTarget\": {
        \"HostedZoneId\": \"${HZ}\",
        \"DNSName\": \"${TARGET}\",
        \"EvaluateTargetHealth\": false
      }
    }
  }]
}" --query 'ChangeInfo.Id' --output text

# ---- Step 5: Verify -------------------------------------------------------
echo "==> [5/5] Waiting 20s for DNS and testing..."
sleep 20
echo -n "    https://${NODE_DOMAIN}/health: "
curl -sf -m 10 "https://${NODE_DOMAIN}/health" || echo "NOT YET (retry in a minute)"
echo

echo "Done. Add this node to the well-known JSON manually:"
echo "  {\"id\": ${NODE_ID}, \"url\": \"https://${NODE_DOMAIN}\", \"platform\": \"nitro\", ...}"
