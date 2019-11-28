#!/bin/bash
#
# This script renews letsencrypt certificates with a given csr and private key file
# thereby maintaining the same SPKI hash for use with TLSA and DANE
# Author: Robert Strasser <avasilencia@pc-tiptop.de>
#

# usage: renew-letsencrypt-tlsa.sh -d www.domain.tld -m <dnsAlternativeNamesFile> -w [apache|nginx]
#        optionally if using dovecot and postfix, specify the option -e true


############################################
## TODO:
## - CSR generation for additional Domains if newly added
############################################

# getting and setting script directory
SCRIPTDIR=$( dirname "$(readlink -f "$0")" )

# import openssl CSR configuration
source $SCRIPTDIR/openssl.conf

# import general settings
source $SCRIPTDIR/settings.conf

# checking if console log path exists, if not create it
if [ ! -d "$consoleLogPath" ]; then
  mkdir -p $consoleLogPath
fi

# write output to logfile
exec > >(tee -i ${consoleLog})
exec 2>&1

# get IPv4 and IPv6 address of local webserver interface
localIPv4=$( ip address show dev $webserverInterface scope global | awk '/inet / {split($2,var,"/"); print var[1]}' )
if [ $IPv6active == "yes" ] ; then
	localIPv6=$( ip address show dev $webserverInterface scope global | awk '/inet6 / {split($2,var,"/"); print var[1]}' )
fi

# get options from command line
while getopts ":d:e:m:w:" opt; do
  case $opt in
	d)	domainCN="$OPTARG"
		echo "Domain name is set to: $domainCN"
    ;;
	e)  email=true
		echo "Note: email server option is set."
	;;
	m)  multipleDnsAlternativeNames=true
		dnsAlternativeNamesFile="$OPTARG"
		echo "Note: additional DNS subject alternative names option is set using input file $dnsAlternativeNamesFile"
		# checking if dnsAlternativeNamesFile exists, if not exit
		if [ ! -f $dnsAlternativeNamesFile ]; then
			echo "Error, you selected the option -m, but $dnsAlternativeNamesFile is not found!"
			echo "For additional DNS alternative names, you must provide the file $dnsAlternativeNamesFile"
			echo "in the script root folder specifying each alternative subject name on a separate line"
			exit 1;
		else 
			# declaring dnsAlternativeNames as an indexed array
			declare -a dnsAlternativeNames
			# Reading in the lines of dnsAlternativeNamesFile
			readarray -t dnsAlternativeNames < $dnsAlternativeNamesFile
			# storing length of dnsAlternativeNames array in variable
			dnsAlternativeNamesSum=${#dnsAlternativeNames[@]}
		fi			
	;;
	w)  webserver="$OPTARG"
	    if [ "$webserver" == "nginx" ]; then 
			nginx=true
			echo "Note: webserver is set to nginx."
		elif [ "$webserver" == "apache" ]; then
			apache=true
			echo "Note: webserver is set to apache."
		else
			echo "error: unsupported webserver option"
			echo "for nginx use: -w nginx"
			echo "for apache use: -w apache"
			exit 1;
		fi
	;;
    \?) echo "Invalid option -$OPTARG" >&2
		echo 'usage: renew-letsencrypt-tlsa.sh -d www.domain.tld -m <dnsAlternativeNamesFile> -w [apache|nginx]'
		echo 'optionally: if dovecot and postfix use this certificate also, set "-e true" to restart them'
		# exit if option is invalid
		exit 1; 
    ;;
  esac
done
#########################################

### CHECKING IF domainCN variable is set
if [ -z "$domainCN" ]; then
    echo "Error: domainname not specified, please use the following option" 
    echo "-d domainname"
    exit 64;
fi

if [ -z "$webserver" ]; then
    echo "Error: webserver is not specified, please use the following option" 
    echo "-w nginx or -w apache"
    exit 64;
fi

### OTHER VARIABLES ###
certFilename="$domainCN.pem"
csrFilename="$domainCN.csr.pem"
csrConfigFileName="/etc/ssl/csr/$domainCN-csr.conf"
privateKeyFilename="$domainCN.privkey.pem"
certificateChainFilename="chain.pem"
fullChainFilename="fullchain.pem"
letsencryptLogDir="/var/log/letsencrypt"
NOW=$(date +%s)
genCertCommand="certbot certonly --agree-tos --standalone --non-interactive --email $email --csr $certPath/$domainCN/$csrFilename --cert-path $certPath/$domainCN/$certFilename --key-path $certPath/$domainCN/$privateKeyFilename --rsa-key-size 4096 --chain-path $certPath/$domainCN/$certificateChainFilename --fullchain-path $certPath/$domainCN/$fullChainFilename --logs-dir $letsencryptLogDir --quiet -d $domainCN"
###########################################

### check if DNS resolution of domains points to this host/webserver
domainIPv4=$( dig +short $domainCN a | grep -v '\.$' )
if [ "$localIPv4" != "$domainIPv4" ] ; then
	echo ""
	echo "Error: $domainCN does not resolve to local IPv4 address $localIPv4" 
    echo "please adjust your DNS settings"
	dnsError="yes"
fi 

if [ $IPv6active == "yes" ] ; then
	domainIPv6=$( dig +short $domainCN aaaa | grep -v '\.$' )
	if [ "$localIPv6" != "$domainIPv6" ] ; then
		echo ""
		echo "Error: $domainCN does not resolve to local IPv6 address $localIPv6" 
		echo "please adjust your DNS settings"
	dnsError="yes"
	fi 
fi

### ADJUSTING genCertCommand for additional DNS subject alternative names
if [ "$multipleDnsAlternativeNames" = true ] ; then
		echo ""
		echo "### Alternative Names Section ###"	
		echo "added the following $dnsAlternativeNamesSum DNS alternative subject names to certificate:"
		let i=0
		while (( ${#dnsAlternativeNames[@]} > i )); do
			echo "${dnsAlternativeNames[i]}"
			# check if DNS alternative name resolves properly to host/webserver IPs
			domainIPv4=$( dig +short ${dnsAlternativeNames[i]} a | grep -v '\.$' )
			
			if [ "$localIPv4" != "$domainIPv4" ] ; then
				echo ""
				echo "Error: ${dnsAlternativeNames[i]} does not resolve to local IPv4 address $localIPv4" 
				echo "please adjust your DNS settings"
				dnsError="yes"
			fi 

			if [ $IPv6active == "yes" ] ; then
				domainIPv6=$( dig +short ${dnsAlternativeNames[i]} aaaa | grep -v '\.$' )
				if [ "$localIPv6" != "$domainIPv6" ] ; then
					echo ""
					echo "Error: ${dnsAlternativeNames[i]} does not resolve to local IPv6 address $localIPv6" 
					echo "please adjust your DNS settings"
					dnsError="yes"
				fi 	
			fi	
			# add DNS alternative name to command
			genCertCommand="$genCertCommand -d ${dnsAlternativeNames[i++]}"
		done
	fi
##########################################

if [ "$dnsError" != "yes" ] ; then
	### CHECKING DIRECTORIES and FILES ###
	# checking if directory exists, if not create it
	if [ ! -d "$certPath/$domainCN" ]; then
	  mkdir -p $certPath/$domainCN
	fi

	# checking if private key file exist, if not create it
	if [ ! -f $certPath/$domainCN/$privateKeyFilename ]; then
		echo ""
		echo "### Private Key Section ###"
		echo "Note: $certPath/$domainCN/$privateKeyFilename not found!"
		echo "Private Key is required for this script to work"
		echo "Generating private key $certPath/$domainCN/$privateKeyFilename with RSA 4096"
		openssl genrsa -out $certPath/$domainCN/$privateKeyFilename 4096
	fi

	# generating csr file with specified settings from openssl.conf
	echo -e "\n"
	echo "### CSR Section ###"
	echo "Generating CSR configuration file /etc/ssl/csr/$domainCN-csr.conf"

	# checking if directory exists, if not create it
	if [ ! -d "/etc/ssl/csr/" ]; then
	  echo "/etc/ssl/csr directory did not exist, creating it"
	  mkdir -p /etc/ssl/csr/
	fi
	   
	# checking if csr file already exists, if yes then delete it
	if [ -f $csrConfigFileName ]; then
	  rm -rf $csrConfigFileName
	fi
	   
	# writing openssl CSR configuration 
	echo "[req]" >> $csrConfigFileName
	echo "distinguished_name = req_distinguished_name" >> $csrConfigFileName
	echo "req_extensions = v3_req" >> $csrConfigFileName
	echo "prompt = no" >> $csrConfigFileName
	echo "[req_distinguished_name]" >> $csrConfigFileName
	echo "C = $COUNTRY" >> $csrConfigFileName
	echo "ST = $STATE" >> $csrConfigFileName
	echo "L = $CITY" >> $csrConfigFileName
	echo "O = $ORGANIZATION" >> $csrConfigFileName
	echo "OU = $DEPARTMENT" >> $csrConfigFileName
	echo "CN = $domainCN" >> $csrConfigFileName
	echo "[v3_req]" >> $csrConfigFileName
	echo "keyUsage = keyEncipherment, dataEncipherment" >> $csrConfigFileName
	echo "extendedKeyUsage = serverAuth" >> $csrConfigFileName
	echo "subjectAltName = @alt_names" >> $csrConfigFileName
	echo "[alt_names]" >> $csrConfigFileName
	echo "DNS.1 = $domainCN" >> $csrConfigFileName
	##########################################

	# add additional alternative subject DNS names to CSR if set
	if [ "$multipleDnsAlternativeNames" = true ] ; then
		let j=0
		# first dns entry is already present, start with DNS.2 and increment
		dnsCount=2;
		while (( ${#dnsAlternativeNames[@]} > j )); do
			echo "DNS.$dnsCount = ${dnsAlternativeNames[j++]}" >> $csrConfigFileName
			((dnsCount++))
		done
	fi

	# finally create actual CSR file with openssl command
	openssl req -new -out $certPath/$domainCN/$csrFilename -key $certPath/$domainCN/$privateKeyFilename -config /etc/ssl/csr/$domainCN-csr.conf
	##########################################


	# check if certificate already exists, evaluate its validity
	if [ ! -f $certPath/$domainCN/$certFilename ]; then
	  # if certificate does not exist set validity to 0
		CERT_VALIDITY=0
	else
	  # if certificate exists read validity end date
		OPENSSL_ENDDATE="$(openssl x509 -enddate -noout -in $certPath/$domainCN/$certFilename)"
		# cutting first 9 letters of openssl output to get clean end date
		CERT_ENDDATE=${OPENSSL_ENDDATE:9}
		# convert to seconds EPOCH
		CERT_ENDDATE=$(date -d "$CERT_ENDDATE" +%s)
		# computing validity days
		CERT_VALIDITY=$((($CERT_ENDDATE - $NOW) / (24*3600)))
				
		if [ "$multipleDnsAlternativeNames" = true ] ; then
		let i=0
		while (( ${#dnsAlternativeNames[@]} > i )); do
			# check if new DNS alternative names have changed or have been added, if so set CERT_VALIDITY to 0, 
			# so that certificate will be renewed with new/changed DNS alternative names
			# store previous DNS alternative names
			PREVIOUS_CERT_ALTERNATIVE_NAMES=$( openssl x509 -text -noout -in $certPath/$domainCN/$certFilename -certopt no_subject,no_header,no_version,no_serial,no_signame,no_validity,no_issuer,no_pubkey,no_sigdump,no_aux | grep DNS: | sed 's/\<DNS\>://g' | sed 's/[[:blank:]]//g' )
			# check if new DNS alternative names are already in the previous certificate, if not set CERT_VALIDITY to 0
			if	[[ "$PREVIOUS_CERT_ALTERNATIVE_NAMES" != *"${dnsAlternativeNames[i]}"* ]] ; then
				echo "${dnsAlternativeNames[i]} not contained in previous certificate's DNS alternative names"
				echo "Previous alternative names have been: $PREVIOUS_CERT_ALTERNATIVE_NAMES"
			fi
			# increment counter
			((i=i+1))
		done
		fi
	fi
	###################################################
	
	### RENEWING CERTIFICATE ###
	# if valid less then 14 days renew
	# if certificate does not exist create new certificate
	if [ $CERT_VALIDITY -lt 14 ]
	then
		### STOPPING WEBSERVER(S) ###
		if [ "$nginx" = true ] ; then
			echo "Stopping nginx"
			systemctl stop nginx
		fi
		
		if [ "$apache" = true ] ; then
			echo "Stopping apache2"
			systemctl stop apache2
		fi
	  ###########################################

	  # make a backup of previous certificate files
		mkdir $certPath/$domainCN/$NOW
		if [ -f $certPath/$domainCN/$certificateChainFilename ]; then
			mv $certPath/$domainCN/$certificateChainFilename $certPath/$domainCN/$NOW/$certificateChainFilename
			echo "old chainfile moved to $certPath/$domainCN/$NOW/$certificateChainFilename"
		fi

		if [ -f $certPath/$domainCN/$fullChainFilename ]; then
			mv $certPath/$domainCN/$fullChainFilename $certPath/$domainCN/$NOW/$fullChainFilename
			echo "old fullchain file moved to $certPath/$domainCN/$NOW/$fullChainFilename"
		fi
		
		if [ -f $certPath/$domainCN/$certFilename ]; then
			mv $certPath/$domainCN/$certFilename $certPath/$domainCN/$NOW/$certFilename
			echo "old certificate moved to $certPath/$domainCN/$NOW/$certFilename"
		fi
	  ############################################
	 
	  ### RENEW CERTIFICATE ###
		# non-interactively renew certificates with specified private key and certificate request file
		eval $genCertCommand
		############################################
	  
	  ### RESTARTING WEBSERVER(S) ###
		if [ "$nginx" = true ] ; then
			echo "Starting nginx"
			systemctl start nginx
		fi
		if [ "$apache" = true ] ; then
			echo "Starting apache2"
			systemctl start apache2
		fi
		############################################
		
	  
	  ### RELOAD CONFIGURATION to use new certificate ###
	   if [ "$nginx" = true ] ; then
			echo "Reloading config for nginx..."
			systemctl reload nginx
		fi
		
		if [ "$apache" = true ] ; then
			echo "Reloading config for apache2..."
			systemctl reload apache2
		fi
		
		if [ "$email" = true ] ; then
			echo "Reloading config for postfix and dovecot..."
			systemctl reload postfix
			systemctl reload dovecot
		fi
	  ############################################

	  ### PRINT SUMMARY ###
		echo ""
		echo "### Summary Section ###"
		echo "--------"
		echo "Domain name: $domainCN"
		echo "Certficate: $certPath/$domainCN/$certFilename"
		echo "Private Key: $certPath/$domainCN/$privateKeyFilename"
		echo "Chain File: $certPath/$domainCN/$certificateChainFilename"
		echo "Full Chain File: $certPath/$domainCN/$fullChainFilename"
		echo "Renewed, validity was $CERT_VALIDITY days"
	  
	else
	  ### DO NOT RENEW ###

	  ### PRINT SUMMARY ###
		echo ""
		echo "### Summary Section ###"
		echo "--------"
		echo "Domain name: $domainCN"
		echo "Certficate: $certPath/$domainCN/$certFilename"
		echo "Private Key: $certPath/$domainCN/$privateKeyFilename"
		echo "Chain File: $certPath/$domainCN/$certificateChainFilename"
		echo "Full Chain File: $certPath/$domainCN/$fullChainFilename"
		echo "Nothing done, validity ok, $CERT_VALIDITY days remaining"
	  ############################################
	fi

	### OUTPUT TLSA Record SPKI ###
	echo ''
	echo 'The TLSA DNS Record for the Certificate is:'
	echo '--------------------------------------------'
	printf '_443._tcp.%s. IN TLSA 3 1 1 %s\n' \
		$domainCN \
		$(openssl req -in $certPath/$domainCN/$csrFilename -noout -pubkey |
			openssl pkey -pubin -outform DER |
			openssl dgst -sha256 -binary |
			hexdump -ve '/1 "%02x"')
	############################################
fi

# if a DNS error occurred set CERT_VALIDITY to 0, to trigger email alert
if [ "$dnsError" == "yes" ] ; then
	CERT_VALIDITY=0
fi
# send an email if validity is less than 14 days or if a DNS resolution error occurred 
if [ $CERT_VALIDITY -lt 14 ] ; then
    mailx -a "From: "$host" Certificates <"$reportemail_from">" -s "Certificate Script | "$host $reportemail_to < $consoleLog
fi
