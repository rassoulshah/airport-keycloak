#!/bin/bash

# Script to automatically retrieve Keycloak client secret
# Make sure Keycloak is running and configured first!

KEYCLOAK_URL="http://localhost:8080"
REALM="airport-realm"
CLIENT_ID="airport-service"
ADMIN_USERNAME="admin"
ADMIN_PASSWORD="admin123"

echo "Getting Keycloak client secret..."

# Get admin access token
echo "1. Getting admin access token..."
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USERNAME" \
  -d "password=$ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to get admin token. Make sure Keycloak is running and credentials are correct."
    exit 1
fi

echo "2. Getting client secret..."
# Get client details
CLIENT_DETAILS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" | jq -r ".[] | select(.clientId==\"$CLIENT_ID\")")

if [ -z "$CLIENT_DETAILS" ]; then
    echo "Client '$CLIENT_ID' not found in realm '$REALM'"
    echo "Please create the client first through Keycloak admin console"
    exit 1
fi

# Extract client UUID
CLIENT_UUID=$(echo $CLIENT_DETAILS | jq -r '.id')

# Get client secret
CLIENT_SECRET=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/clients/$CLIENT_UUID/client-secret" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" | jq -r '.value')

if [ "$CLIENT_SECRET" != "null" ] && [ ! -z "$CLIENT_SECRET" ]; then
    echo "✅ Client Secret: $CLIENT_SECRET"
    echo ""
    echo "Add this to your .env file:"
    echo "KEYCLOAK_CLIENT_SECRET=$CLIENT_SECRET"
else
    echo "❌ Failed to retrieve client secret"
    echo "Make sure client authentication is enabled for the client"
fi