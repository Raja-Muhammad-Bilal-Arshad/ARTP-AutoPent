#!/bin/bash
# =================================================================
# AutoPENT Cloud Vulnerability Seeder (Black Hat Edition)
# Injects realistic misconfigurations into LocalStack
# =================================================================

echo "[*] Waiting for LocalStack to stabilize..."
# Simple wait loop for S3 service
until aws --endpoint-url=http://localstack:4566 s3 ls > /dev/null 2>&1; do
  printf '.'
  sleep 2
done
echo " [OK]"

# =================================================================
# SCENARIO 1: Public S3 Buckets (Data Leakage)
# =================================================================
echo "[+] Creating Vulnerable S3 Buckets..."

# Bucket 1: "financial-backup" (Public Read ACL)
aws --endpoint-url=http://localstack:4566 s3 mb s3://financial-backups-prod
aws --endpoint-url=http://localstack:4566 s3api put-bucket-acl --bucket financial-backups-prod --acl public-read
# Add a sensitive file
echo "{\"db_host\": \"10.0.0.5\", \"db_pass\": \"X8df!9sA\"}" > db_config.json
aws --endpoint-url=http://localstack:4566 s3 cp db_config.json s3://financial-backups-prod/db_config.json

# Bucket 2: "dev-terraform-state" (Hidden, but listable)
aws --endpoint-url=http://localstack:4566 s3 mb s3://dev-terraform-state

# =================================================================
# SCENARIO 2: IAM Privilege Escalation (*:* Policy)
# =================================================================
echo "[+] Creating Over-Permissive IAM Roles..."

# Role: "DeployBot" with AdministratorAccess (Classic mistake)
cat <<EOF > admin-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }
    ]
}
EOF

aws --endpoint-url=http://localstack:4566 iam create-user --user-name deploy-bot
aws --endpoint-url=http://localstack:4566 iam put-user-policy --user-name deploy-bot --policy-name FullAdmin --policy-document file://admin-policy.json
aws --endpoint-url=http://localstack:4566 iam create-access-key --user-name deploy-bot > /tmp/deploy_keys.json

# Save these keys to a public bucket to simulate a "Leak"
aws --endpoint-url=http://localstack:4566 s3 cp /tmp/deploy_keys.json s3://financial-backups-prod/deploy-bot-keys.txt

# =================================================================
# SCENARIO 3: Serverless Secrets (Lambda Env Vars)
# =================================================================
echo "[+] Creating Vulnerable Lambda Function..."

# Function with hardcoded secrets in Environment Variables
cat <<EOF > index.py
def handler(event, context):
    return "Hello from Legacy API"
EOF
zip function.zip index.py

aws --endpoint-url=http://localstack:4566 iam create-role --role-name lambda-ex --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'

aws --endpoint-url=http://localstack:4566 lambda create-function \
    --function-name legacy-payment-processor \
    --runtime python3.8 \
    --zip-file fileb://function.zip \
    --handler index.handler \
    --role arn:aws:iam::000000000000:role/lambda-ex \
    --environment Variables="{STRIPE_API_KEY=sk_live_51Mz9...CRITICAL_SECRET, DB_CONN_STRING=postgres://admin:password@db-prod}"

echo "[✅] Cloud Environment Weaponized. Ready for ARTP."
