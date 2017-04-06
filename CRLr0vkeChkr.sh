#!/bin/bash

echo -e "\e[92m  ___ ___ _         __      _        ___ _    _"
echo -e " / __| _ \ |   _ _ /  \__ _| |_____ / __| |_ | |___ _"
echo -e "| (__|   / |__| '_| () \ V / / / -_) (__| ' \| / / '_|"
echo -e " \___|_|_\____|_|  \__/ \_/|_\_\___|\___|_||_|_\_\_|"
echo -e "______________________________________________________\e[39m"
echo -e "\e[31m*CRL Revocation Checker* by YeYintMinThuHtut\n"
name=$1
port=$2
if [ $# -ne 3 ]
  then
    echo -e '\e[32mUsage: ./CRLr0vkeChkr.sh www.example.com port service'
    echo -e 'Example:  ./CRLr0vkeChkr.sh smtp.yandex.com 25 smtp\e[39m\n'
else
  if [ $3 == "http" ]
   then
    echo -e "\e[93m[+]HTTP CRL Revoke check starting....\e[39m"
	echo -e "\n\e[93m[+][+]Connecting host....\e[39m"
    openssl s_client -connect $name:$port 2>$1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > $name.pem
	cmd="$(openssl x509 -noout -text -in $name.pem | grep -A 4 'X509v3 CRL Distribution Points' | grep -Eo '(http|https)://[^"]*')"
	echo -e "\n\e[93m[+]Finding CRL....\n\e[39m"
	echo -e "\e[93m[+]CRL Found -> ${cmd} \n\e[39m"
	echo -e "\e[93m[+]Downloading CRL....\n\e[39m"
	wget -O $name.crl.der ${cmd}
	echo -e "\e[93m[+]Converting readable form....\n\e[39m"
	openssl crl -inform DER -in $name.crl.der -outform PEM -out $name.crl.pem >$1 < /dev/null
	echo -e "\e[93m[+]Dumpping Cert Chain....\n\e[39m"
	OLDIFS=$IFS; IFS=':' certificates=$(openssl s_client -connect $name:$port -showcerts -tlsextdebug -tls1 2>&1 </dev/null | sed -n '/-----BEGIN/,/-----END/ {/-----BEGIN/ s/^/:/; p}'); for certificate in ${certificates#:}; do echo $certificate | tee -a $name.chain.pem ; done; IFS=$OLDIFS
	cat $name.chain.pem $name.crl.pem > $name.crlchain.pem 2>&1 </dev/null
	echo -e "\n\n\n\e[93m[+]Verifying Revoke....\n\e[39m"
	r0vke=$(openssl verify -crl_check -CAfile $name.crlchain.pem $name.pem)
	echo -e "${r0vke}\n\n"
  else
    if [ $3 == "smtp" ]
    then
     echo -e "\e[93m[+]SMTP CRL Revoke check starting....\n\e[39m"
	 echo -e "\n\e[93m[+]Connecting host....\e[39m"
     openssl s_client -connect $name:$port -starttls smtp 2>$1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > $name.pem
	 cmd="$(openssl x509 -noout -text -in $name.pem | grep -A 4 'X509v3 CRL Distribution Points' | grep -Eo '(http|https)://[^"]*')"
	 echo -e "\n\e[93m[+]Finding CRL....\n\e[39m"
	 echo -e "\e[93m[+]CRL Found -> ${cmd} \n\e[39m"
	 echo -e "\e[93m[+]Downloading CRL....\n\e[39m"
	 wget -O $name.crl.der ${cmd}
	 echo -e "\e[93m[+]Converting readable form....\n\e[39m"
	 openssl crl -inform DER -in $name.crl.der -outform PEM -out $name.crl.pem >$1 < /dev/null
	 echo -e "\e[93m[+]Dumpping Cert Chain....\n\e[39m"
	 OLDIFS=$IFS; IFS=':' certificates=$(openssl s_client -connect $name:$port -showcerts -tlsextdebug -tls1 -starttls smtp 2>&1 </dev/null | sed -n '/-----BEGIN/,/-----END/ {/-----BEGIN/ s/^/:/; p}'); for certificate in ${certificates#:}; do echo $certificate | tee -a $name.chain.pem ; done; IFS=$OLDIFS
	 cat $name.chain.pem $name.crl.pem > $name.crlchain.pem 2>&1 </dev/null
	 echo -e "\n\n\n\e[93m[+]Verifying Revoke....\n\e[39m"
	 r0vke=$(openssl verify -crl_check -CAfile $name.crlchain.pem $name.pem)
	 echo -e "\e[93m ${r0vke} \n\n\e[39m"
     fi
  fi
fi