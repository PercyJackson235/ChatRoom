#!/bin/bash
if [ "$2" == '' ]
then
    cert_dir="certs"
else
    cert_dir="$2"
fi
if [ ! -d $cert_dir ]
then
    mkdir $cert_dir
fi
if [ "$2" == '' ]
then
    domain_name="pythonchatroom.com"
else
    domain_name="$2"
fi
priv_key=$cert_dir"/key.pem"
pub_key=$cert_dir"/cert.pem"
openssl req -newkey rsa:2048 -nodes -keyout $priv_key -x509 -days 7 -out $pub_key \
 -subj "/C=US/ST=NRW/L=Earth/O=CompanyName/OU=IT/CN=$domain_name/emailAddress=email@example.com"
