# IAM Roles for Service Accounts (IRSA) on kops clusters

This is a full example of IAM Roles for Service Accounts (IRSA) on clusters created with kops. 
It uses the official [amazon-eks-pod-identity-webhook](https://github.com/aws/amazon-eks-pod-identity-webhook/blob/master/SELF_HOSTED_SETUP.md)

## Quick start

```bash
git clone https://github.com/alex-ferener/aws-irsa-kops
cd aws-irsa-kops

./deploy-oidc-endpoint.sh

# Update cluster config (see template in step 2)
kops rolling-update cluster

./gen-identity-webhook-cert.sh
kubectl apply -f identity-webhook/

./test-s3-list.sh
```

### 1. Deploy OIDC Endpoint

```bash
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
```

### 2. kops configuration

Replace `serviceAccountIssuer`, `sa-signer-pkcs8.pub` and `sa-signer.key` in cluster template

```yaml
spec:
  serviceAccountKeyFile:
    - /etc/kubernetes/pki/kube-apiserver/sa-signer-pkcs8.pub
    - /srv/kubernetes/server.key
  serviceAccountSigningKeyFile: /etc/kubernetes/pki/kube-apiserver/sa-signer.key
  apiAudiences:
    - sts.amazonaws.com
  serviceAccountIssuer: https://**REPLACE_WITH_OIDC_ISSUER_ENDPOINT**
  fileAssets:
    - name: sa-signer-pkcs8.pub
      path: /etc/kubernetes/pki/kube-apiserver/sa-signer-pkcs8.pub
      roles: [Master]
      content: |
        -----BEGIN PUBLIC KEY-----
        **REPLACE WITH** the file generated in step 1 -> cat ./oidc/sa-signer-pkcs8.pub
    - name: sa-signer.key
      path: /etc/kubernetes/pki/kube-apiserver/sa-signer.key
      roles: [Master]
      content: |
        -----BEGIN RSA PRIVATE KEY-----
        **REPLACE WITH** the file generated in step 1 -> cat ./oidc/sa-signer.key
```

Apply the cluster config: `kops edit` + `kops update` + `kops rolling-update` (only for masters)

### 3. Deploy Pod Identity Webhook

Generate the TLS certificate required by `pod-identity-webhook` and patch `caBundle` from `MutatingWebhookConfiguration`

```
CERTIFICATE_PERIOD=365
POD_IDENTITY_SERVICE_NAME=pod-identity-webhook
POD_IDENTITY_SECRET_NAME=pod-identity-webhook
POD_IDENTITY_SERVICE_NAMESPACE=kube-system

CERT_DiR=$PWD/cert
mkdir $CERT_DiR

openssl req \
  -x509 -nodes \
  -newkey rsa:2048 \
  -keyout $CERT_DiR/tls.key \
  -out $CERT_DiR/tls.crt \
  -days $CERTIFICATE_PERIOD \
  -subj "/CN=$POD_IDENTITY_SERVICE_NAME.$POD_IDENTITY_SERVICE_NAMESPACE.svc"

kubectl create secret generic $POD_IDENTITY_SECRET_NAME \
  --from-file=$CERT_DiR/tls.crt \
  --from-file=$CERT_DiR/tls.key \
  --namespace=$POD_IDENTITY_SERVICE_NAMESPACE

CA_BUNDLE=$(cat $CERT_DiR/tls.crt | base64 | tr -d '\n')

sed -i "s/caBundle:.*/caBundle: ${CA_BUNDLE}/" $CERT_DiR/../identity-webhook/mutatingwebhook.yaml
```

Deploy Pod Identity Webhook

```bash
kubectl apply -f identity-webhook/
```

### 4. Testing

```bash
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

kubectl create -n default sa s3-list
kubectl annotate -n default sa s3-list eks.amazonaws.com/role-arn=arn:aws:iam::$ACCOUNT_ID:role/$ROLE_NAME

sleep 8

kubectl run -n default s3-list -i --rm --image amazon/aws-cli --generator=run-pod/v1 --serviceaccount=s3-list -- s3 ls
```

### 5. Cleanup

```bash
kubectl delete -f identity-webhook/
kubectl delete secret pod-identity-webhook -n kube-system
aws s3 rb s3://$S3_BUCKET --force
```
