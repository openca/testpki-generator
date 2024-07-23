#!/bin/bash

OSSL_CMD=$(type -path openssl)

case "$1" in 
  -h|--help)
    echo "Usage: $0"
    echo "Generates the PKI for the project"
    exit 0
    ;;
  -v|--version)
    echo "Version: 0.1"
    exit 0
    ;;
  -d|--debug)
    set -x
    shift
    ;;
  -q|--quiet)
    exec 1>/dev/null
    shift
    ;;
  -p|--pqc)
    shift
    . ./params/pqc-params.sh
    ;;
  -t|--trad)
    shift
    . ./params/trad-params.sh
    ;;
  -c|--comp)
    shift
    . ./params/comp-params.sh
    ;;
esac

for i in params/*.sh ; do
  
  # Some Debugging Info
  echo "Loading $i ..."

  # Loads the parameters
  . $i

  # Creates the PKI directory, if it does not exsists
  mkdir -p PKIs/$OUT_DIR/private
  mkdir -p PKIs/$OUT_DIR/requests
  mkdir -p PKIs/$OUT_DIR/chains
  mkdir -p PKIs/$OUT_DIR/certs
  mkdir -p PKIs/$OUT_DIR/ocsp

  # Generates the private keys
  res=$(cd PKIs/$OUT_DIR \
        && openssl genpkey -algorithm $ROOT_ALG $ROOT_PARAMS -outform DER -out private/root.private \
        && openssl genpkey -algorithm $ICA_ALG $ICA_PARAMS -outform DER -out private/ica.private  \
        && openssl genpkey -algorithm $EE_ALG $EE_PARAMS -outform DER -out private/server.private \
        && openssl genpkey -algorithm $EE_ALG $EE_PARAMS -outform DER -out private/client.private \
        && openssl genpkey -algorithm $EE_ALG $EE_PARAMS -outform DER -out private/ocsp.private \
        && openssl genpkey -algorithm $EE_ALG $EE_PARAMS -outform DER -out private/cvc.private )

  # Generates the CSRs
  res=$(cd PKIs/$OUT_DIR \
        && openssl req -new -key private/root.private -inform DER -outform DER -out requests/root.request -subj "/CN=$OUT_DIR ROOT CA" 2>/dev/null > /dev/null \
        && openssl req -new -key private/ica.private -outform DER -outform DER -out requests/ica.request -subj "/CN=$OUT_DIR INTERMEDIATE CA" 2>/dev/null > /dev/null \
        && openssl req -new -key private/server.private -inform DER -outform DER -outform DER -out requests/server.request -subj "/CN=$OUT_DIR Server Certificate" 2>/dev/null > /dev/null \
        && openssl req -new -key private/client.private -inform DER -outform DER -outform DER -out requests/client.request -subj "/CN=$OUT_DIR Client Certificate" 2>/dev/null > /dev/null \
        && openssl req -new -key private/ocsp.private -inform DER -outform DER -outform DER -out requests/ocsp.request -subj "/CN=$OUT_DIR OCSP Responder Certificate" 2>/dev/null > /dev/null \
        && openssl req -new -key private/cvc.private -inform DER -outform DER -outform DER -out requests/cvc.request -subj "/CN=$OUT_DIR CVC Certificate" 2>/dev/null > /dev/null )

  # Generates the certificates
  res=$(cd PKIs/$OUT_DIR \
        && openssl x509 -req -key private/root.private -keyform DER -outform DER -in requests/root.request -out certs/root.cert -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/root.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/root.private -keyform DER -CA certs/root.cert -outform DER -in requests/ica.request -out certs/ica.cert -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/ica.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cert -outform DER -in requests/server.request -out certs/server.cert -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/server.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cert -outform DER -in requests/client.request -out certs/client.cert -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/client.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cert -outform DER -in requests/ocsp.request -out certs/ocsp.cert -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/ocsp.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cert -outform DER -in requests/cvc.request -out certs/cvc.cert -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/cvc.profile 2>/dev/null > /dev/null )

  # TODO: Sign CRLs

  # Signs the OCSP responses for the generated certificates
  # serial=$(openssl x509 -serial -in certs/root.cert -inform DER -noout | cut -d= -f2)
  res=$(cd PKIs/$OUT_DIR \
        && echo -n > index.txt \
        && openssl ocsp -rsigner certs/root.cert -rkey private/root.private -respout ocsp/ica.ocsp -index index.txt -CA certs/root.cert -issuer certs/root.cert -cert certs/ica.cert -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cert -rkey private/ica.private -respout ocsp/server.ocsp -index index.txt -CA certs/root.cert -issuer certs/ica.cert -cert certs/server.cert -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cert -rkey private/ica.private -respout ocsp/client.ocsp -index index.txt -CA certs/root.cert -issuer certs/ica.cert -cert certs/client.cert -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cert -rkey private/ica.private -respout ocsp/ocsp.ocsp -index index.txt -CA certs/root.cert -issuer certs/ica.cert -cert certs/ocsp.cert -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cert -rkey private/ica.private -respout ocsp/cvc.ocsp -index index.txt -CA certs/root.cert -issuer certs/ica.cert -cert certs/cvc.cert -ndays 365000 )

  # Builds the chain files
  res=$(cd PKIs/$OUT_DIR \
        && cat certs/server.cert certs/ica.cert > chains/server.chain \
        && cat certs/client.cert certs/ica.cert > chains/client.chain \
        && cat certs/ocsp.cert certs/ica.cert > chains/ocsp.chain \
        && cat certs/cvc.cert certs/ica.cert > chains/cvc.chain )

done

exit 0
