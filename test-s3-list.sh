#!/bin/bash
set -e

ROLE_NAME=s3-list
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
OIDC_PROVIDER=$(cat ./oidc/oidc-provider)
OIDC_PROVIDER_ARN="arn:aws:iam::$ACCOUNT_ID:oidc-provider/$OIDC_PROVIDER"

# Use `StringLike` and `*` instead of `$ROLE_NAME` if you want to scope a role to an entire namespace
cat > trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "$OIDC_PROVIDER_ARN"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:default:$ROLE_NAME"
        }
      }
    }
  ]
}
EOF

aws iam create-role --role-name $ROLE_NAME --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name $ROLE_NAME --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

kubectl config set-context --current --namespace=default
kubectl create -n default sa s3-list
kubectl annotate -n default sa s3-list eks.amazonaws.com/role-arn=arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME

sleep 8

kubectl run -n default s3-list -i --rm --image amazon/aws-cli --generator=run-pod/v1 --serviceaccount=s3-list -- s3 ls

rm -f trust-policy.json
