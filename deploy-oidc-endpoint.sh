#!/bin/bash
set -e

OIDC_DIR=$PWD/oidc
mkdir $OIDC_DIR

PRIV_KEY="$OIDC_DIR/sa-signer.key"
PUB_KEY="$OIDC_DIR/sa-signer.key.pub"
PKCS_KEY="$OIDC_DIR/sa-signer-pkcs8.pub"
ssh-keygen -t rsa -b 2048 -f $PRIV_KEY -m pem -q -N ""
ssh-keygen -e -m PKCS8 -f $PUB_KEY > $PKCS_KEY

AWS_REGION=$(aws configure get region)

export S3_BUCKET="oidc-irsa-$(cat /dev/random | LC_ALL=C tr -dc "[:alpha:]" | tr '[:upper:]' '[:lower:]' | head -c 8)"
export OIDC_PROVIDER="s3-$AWS_REGION.amazonaws.com/$S3_BUCKET"

aws s3api create-bucket --bucket $S3_BUCKET --create-bucket-configuration LocationConstraint=$AWS_REGION > /dev/null

cat <<EOF > $OIDC_DIR/discovery.json
{
    "issuer": "https://$OIDC_PROVIDER/",
    "jwks_uri": "https://$OIDC_PROVIDER/keys.json",
    "authorization_endpoint": "urn:kubernetes:programmatic_authorization",
    "response_types_supported": [
        "id_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "claims_supported": [
        "sub",
        "iss"
    ]
}
EOF

if [[ "$(uname -s)" =~ "Darwin" ]]; then
  ./bin/generate-oidc-keys-json-darwin -key $PKCS_KEY | jq '.keys += [.keys[0]] | .keys[1].kid = ""' > $OIDC_DIR/keys.json
else
  ./bin/generate-oidc-keys-json-linux -key $PKCS_KEY | jq '.keys += [.keys[0]] | .keys[1].kid = ""' > $OIDC_DIR/keys.json
fi

aws s3 cp --acl public-read $OIDC_DIR/discovery.json s3://$S3_BUCKET/.well-known/openid-configuration
aws s3 cp --acl public-read $OIDC_DIR/keys.json s3://$S3_BUCKET/keys.json

CA_THUMBPRINT=$(openssl s_client -connect s3-$AWS_REGION.amazonaws.com:443 -servername s3-$AWS_REGION.amazonaws.com \
  -showcerts < /dev/null 2>/dev/null | openssl x509 -in /dev/stdin -sha1 -noout -fingerprint | cut -d '=' -f 2 | tr -d ':')

aws iam create-open-id-connect-provider \
     --url https://$OIDC_PROVIDER \
     --thumbprint-list $CA_THUMBPRINT \
     --client-id-list sts.amazonaws.com

echo -n $OIDC_PROVIDER > ./oidc/oidc-provider
echo -e "\nOIDC Provider URL: https://$OIDC_PROVIDER\n"
