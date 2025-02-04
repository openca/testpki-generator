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
        && openssl x509 -req -key private/root.private -keyform DER -outform DER -in requests/root.request -out certs/root.cer -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/root.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/root.private -keyform DER -CA certs/root.cer -outform DER -in requests/ica.request -out certs/ica.cer -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/ica.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cer -outform DER -in requests/server.request -out certs/server.cer -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/server.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cer -outform DER -in requests/client.request -out certs/client.cer -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/client.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cer -outform DER -in requests/ocsp.request -out certs/ocsp.cer -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/ocsp.profile 2>/dev/null > /dev/null \
        && openssl x509 -req -CAkey private/ica.private -keyform DER -CA certs/ica.cer -outform DER -in requests/cvc.request -out certs/cvc.cer -not_before 20010101000000Z -not_after 99991231235959Z -extfile ../../profiles/cvc.profile 2>/dev/null > /dev/null )

  # TODO: Sign CRLs

  # Signs the OCSP responses for the generated certificates
  # serial=$(openssl x509 -serial -in certs/root.cer -inform DER -noout | cut -d= -f2)
  res=$(cd PKIs/$OUT_DIR \
        && echo -n > index.txt \
        && openssl ocsp -rsigner certs/root.cer -rkey private/root.private -respout ocsp/ica.ocsp -index index.txt -CA certs/root.cer -issuer certs/root.cer -cert certs/ica.cer -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cer -rkey private/ica.private -respout ocsp/server.ocsp -index index.txt -CA certs/root.cer -issuer certs/ica.cer -cert certs/server.cer -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cer -rkey private/ica.private -respout ocsp/client.ocsp -index index.txt -CA certs/root.cer -issuer certs/ica.cer -cert certs/client.cer -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cer -rkey private/ica.private -respout ocsp/ocsp.ocsp -index index.txt -CA certs/root.cer -issuer certs/ica.cer -cert certs/ocsp.cer -ndays 365000 \
        && openssl ocsp -rsigner certs/ica.cer -rkey private/ica.private -respout ocsp/cvc.ocsp -index index.txt -CA certs/root.cer -issuer certs/ica.cer -cert certs/cvc.cer -ndays 365000 )

  # Builds the chain files
  res=$(cd PKIs/$OUT_DIR \
        && openssl x509 -inform DER -in certs/server.cer > chains/server.chain \
        && openssl x509 -inform DER -in certs/ica.cer >> chains/server.chain \
        && openssl x509 -inform DER -in certs/client.cer > chains/client.chain \
        && openssl x509 -inform DER -in certs/ica.cer >> chains/client.chain \
        && openssl x509 -inform DER -in certs/ocsp.cer > chains/ocsp.chain \
        && openssl x509 -inform DER -in certs/ica.cer >> chains/ocsp.chain \
        && openssl x509 -inform DER -in certs/cvc.cer > chains/cvc.chain \
        && openssl x509 -inform DER -in certs/ica.cer >> chains/cvc.chain )

  # Provides the PKI description
  res=$(cd PKIs/$OUT_DIR \
        && echo "PKI $OUT_DIR:" > description.txt \
        && echo "  Root CA ($ROOT_ALG): certs/root.cer" >> description.txt \
        && echo "  Intermediate CA ($ICA_ALG): certs/ica.cer" >> description.txt \
        && echo "  Server Certificate ($EE_ALG): certs/server.cer" >> description.txt \
        && echo "  Client Certificate ($EE_ALG): certs/client.cer" >> description.txt \
        && echo "  OCSP Responder Certificate ($EE_ALG): certs/ocsp.cer" >> description.txt \
        && echo "  CVC Certificate ($EE_ALG): certs/cvc.cer" )

done

exit 0
