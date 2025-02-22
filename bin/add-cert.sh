#!/bin/bash

# OpenSSL Command Line Tool
OSSL_CMD=$(type -path openssl)
NOW=$(date +%Y%m%d%H%M%S)

# Default Profile
OSSL_PROFILE="server"

# Validity Options
OSSL_30_VALIDITY_OPT="-days 20000"
OSSL_33_VALIDITY_OPT="-not_before 20010101000000Z -not_after 99991231235959Z"
OSSL_VALIDITY_OPT=$OSSL_33_VALIDITY_OPT

# Selects the right options for the installed OSSL version
ret=$($OSSL_CMD version | grep "3.0" )
if [ $? == 0 ] ; then
	OSSL_VALIDITY_OPT=$OSSL_30_VALIDITY_OPT
fi

# Sets the default format
if [ "x$OSSL_FORMAT" = "x" ] ; then
	OSSL_FORMAT="PEM"
fi

# Processes the command line options and allow the user
# to specify the PKI to use and the profile to use. Process
# the command line one by one
case $1 in
  -h|--help)
    echo "Usage: $0"
    echo "Generates the PKI for the project"
    exit 0
    ;;
  -l|--list)
    echo "Available PKIs:"
    echo "---------------"
    ls -1 PKIs
    echo
    echo "Available Profiles:"
    echo "-------------------"
    ls -1 profiles
    echo
    echo "Available Formats:"
    echo "------------------"
    echo "  PEM"
    echo "  DER"
    echo
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
  -f|--format)
    OSSL_FORMAT=$2
    shift 2
  ;;
  -p|--profile)
    OSSL_PROFILE=$2
    shift 2
  ;;
  -s| --subject)
    OSSL_SUBJECT=$2
    shift 2
  ;;
  -o|--output)
    OUT_DIR=$2
    shift 2
  ;;
  *)
    if [ "$1" != "" ] ; then
      echo "Unknown option: $1"
      exit 1
    fi
  ;;
esac

for i in params/*.sh ; do
  
  # Some Debugging Info
  echo "Loading $i ..."

  # Loads the parameters
  . $i

  # Generates the private key
  res=$(cd PKIs/$OUT_DIR \
        && openssl genpkey -algorithm $EE_ALG $EE_PARAMS -outform $OSSL_FORMAT -out private/$NOW.private )

if [ "x$OSSL_SUBJECT" = "x" ] ; then
  OSSL_SUBJECT="/CN=$OUT_DIR $OSSL_PROFILE Certificate"
fi

  # Generates the CSRs
  res=$(cd PKIs/$OUT_DIR \
        && openssl req -new -key private/$NOW.private -inform $OSSL_FORMAT -outform $OSSL_FORMAT -outform $OSSL_FORMAT -out requests/$NOW.request -subj "$OSSL_SUBJECT" 2>/dev/null > /dev/null )

  # Generates the certificates
  res=$(cd PKIs/$OUT_DIR \
        && openssl x509 -req -CAkey private/ica.private -CAkeyform $OSSL_FORMAT -CA certs/ica.cer -CAform $OSSL_FORMAT -inform $OSSL_FORMAT -outform $OSSL_FORMAT -in requests/$NOW.request -out certs/$NOW.cer -extfile ../../profiles/$OSSL_PROFILE.profile $OSSL_VALIDITY_OPT )

  # TODO: Sign CRLs

  # Signs the OCSP responses for the generated certificates
  # serial=$(openssl x509 -serial -in certs/root.cer -inform $OSSL_FORMAT -noout | cut -d= -f2)
  res=$(cd PKIs/$OUT_DIR \
        && echo -n > index.txt \
        && openssl ocsp -rsigner certs/ica.cer -rkey private/ica.private -respout ocsp/$NOW.ocsp -index index.txt -CA certs/root.cer -issuer certs/ica.cer -cert certs/$NOW.cer -ndays 365000 )

  # Builds the chain files
  res=$(cd PKIs/$OUT_DIR \
        && openssl x509 -inform $OSSL_FORMAT -in certs/$NOW.cer > chains/$NOW.chain \
        && openssl x509 -inform $OSSL_FORMAT -in certs/ica.cer >> chains/$NOW.chain )

  # Provides the Certificate description
  res=$(cd PKIs/$OUT_DIR \
	  && echo "PKI $OUT_DIR (format: $OSSL_FORMAT):" \
        && echo "  Profile: $OSSL_PROFILE" \
        && echo "  Algorithm: $EE_ALG" \
        && echo "  Subject DN: $OSSL_SUBJECT" \
        && echo "  Output File ($EE_ALG): certs/$NOW.cer" )

done

exit 0
