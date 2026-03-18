#!/bin/bash
NODE=$1
IP=$2

# Usamos la variable de entorno genérica
CERTS_DIR="./quditto_certs"

mkdir -p $CERTS_DIR
cd $CERTS_DIR

# 1. Crear la Autoridad Certificadora (CA) exclusiva de este nodo
openssl genrsa -out ${NODE}_ca.key 2048
openssl req -x509 -new -nodes -key ${NODE}_ca.key -sha256 -days 3650 -out ${NODE}_ca.crt -subj "/CN=QKD_CA_Node_${NODE}"

# 2. Crear Certificado del Servidor (El Nodo QKD)
openssl genrsa -out ${NODE}_node.key 2048
openssl req -new -key ${NODE}_node.key -out ${NODE}_node.csr -subj "/CN=${NODE}_Server" -addext "subjectAltName = IP:${IP}"
openssl x509 -req -in ${NODE}_node.csr -CA ${NODE}_ca.crt -CAkey ${NODE}_ca.key -CAcreateserial -out ${NODE}_node.crt -days 365 -sha256 -extfile <(printf "subjectAltName=IP:${IP}")

# 3. Crear Certificado del Cliente Autorizado (El SAE)
openssl genrsa -out SAE_${NODE}.key 2048
openssl req -new -key SAE_${NODE}.key -out SAE_${NODE}.csr -subj "/CN=SAE_Authorized_by_${NODE}"
openssl x509 -req -in SAE_${NODE}.csr -CA ${NODE}_ca.crt -CAkey ${NODE}_ca.key -CAcreateserial -out SAE_${NODE}.crt -days 365 -sha256

echo "Certificados generados correctamente en $CERTS_DIR para el Nodo ${NODE}"