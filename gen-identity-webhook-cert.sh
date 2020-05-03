#!/bin/bash
set -e

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
