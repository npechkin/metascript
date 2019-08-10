#!/bin/bash
# METAHASH TOOL
# app://ForgingMHC#!/delegation/server/0x00f0bec7a7b832d4400455229103c6cec3abd6736f60152b6d
# For MHC delegation. (Geo CN. Reward 90%|95% for > 100k MHC.) And for donats.

scriptname=$0
vars=("$@")

usage () {
echo -e "Usage: $scriptname option [parameter]
List of options:
usage -- display help info.
generate -- generate MetaHash address with OpenSSL Tool.
enc-private-key -- encrypt your private key with password (for MetaGate).
\t --net=NETWORK(dev|main|test)
\t --privkey=/path/to/private_key
dec-private-key -- decrypt encrypted private key.
\t --net=NETWORK(dev|main|test)
\t --ecpriv=/path/to/ecpriv_key
gen-public-key -- generate public key from private key.
\t --net=NETWORK(dev|main|test)
\t --privkey=/path/to/private_key
get-address -- get your own metahash address.
\t --net=NETWORK(dev|main|test)
\t --pubkey=/path/to/public_key
show-private-key -- show key for proxy.
\t --net=NETWORK(dev|main|test)
\t --privkey=/path/to/private_key
show-public-key -- show public key DER16.
\t --net=NETWORK(dev|main|test)
\t --privkey=/path/to/private_key
fetch-balance -- get balance information.
\t --net=NETWORK(dev|main|test)
\t --address=metahash_address
fetch-history -- get history for address.
\t --net=NETWORK(dev|main|test|test)
\t --address=metahash_address
get-tx -- get transaction information.
\t --net=NETWORK(dev|main|test)
\t --tx_hash=transacation_hash
gen-transaction -- gives you binary of transaction.
\t --amount=AMOUNT_TO_SEND
\t --send_to=RECEPIENT_ADDRESS
\t --nonce=VALUE
prepare-transaction -- gives you json of transaction.
\t --net=NETWORK(dev|main|test)
\t --pubkey=/path/to/public_key
\t --privkey=/path/to/private_key
\t --amount=AMOUNT_TO_SEND
\t --send_to=RECEPIENT_ADDRESS
\t Optional parameters:
\t --nonce=VALUE
\t --dataHex=DATA_in_HEX
send-transaction -- send a transaction to server.
\t --net=NETWORK(dev|main|test)
\t --pubkey=/path/to/public_key
\t --privkey=/path/to/private_key
\t --amount=AMOUNT_TO_SEND
\t --send_to=RECEPIENT_ADDRESS"
    exit 1
}

generate () {
openssl ecparam -genkey -name secp256k1 -out mh.pem 2>/dev/null
if [ $? -eq 0 ]; then
    echo -n 'Done! '
else
    echo
    echo 'Something went wrong, check your openssl installation'
    exit 127
fi
openssl ec -in mh.pem -pubout -out mh.pub 2>/dev/null
openssl ec -in mh.pem -out mh.ec.priv -aes256 2>/dev/null
echo -e 'Private key saved as mhdec.pem, mhenc.pem, public as mh.pub in key directory.
YOUR MUST SAVE YOURS KEYS!!!'
get-address-from-pubkey "from_gen"
echo -e "Your metahash address is $metahash_address"
}

enc-private-key () {
get-config
echo privkey=$privkey
openssl ec -in $privkey -out mh.ec.priv -aes256 2>/dev/null
}

dec-private-key () {
get-config
echo ecpriv=$ecpriv
openssl ec -in $ecpriv -out mh.pem 2>/dev/null
}

gen-public-key () {
get-config
echo privkey=$privkey
openssl ec -in $privkey -pubout -out mh.pub 2>/dev/null
}

get-address-from-pubkey () {
if [[ $1 == 'from_gen' ]] || [ -f mh.pub ] && [ -z $pubkey_file ]
then
    pubkey_file=mh.pub
fi
    mh_addr=`mktemp /tmp/mh.XXXXX`
#    echo mh_addr=$mh_addr
    openssl ec -pubin -inform PEM -in $pubkey_file -outform DER 2>/dev/null |tail -c 65|xxd -p -c 65 >$mh_addr
    sha256hashpub=`cat $mh_addr | xxd -r -p | openssl dgst -sha256 2>/dev/null| cut -f 2 -d ' '`
    rmdhash=00`echo -e $sha256hashpub  | xxd -r -p | openssl dgst -rmd160 | cut -f 2 -d ' '`
    sha256rmdhash=`echo -e $rmdhash | xxd -r -p | openssl dgst -sha256 | cut -f 2 -d ' '`
    sha256hash4=`echo -e  $sha256rmdhash | xxd -r -p | openssl dgst -sha256 | cut -f 2 -d ' '`
    hash4=`echo -e $sha256hash4|head -c 8`
    metahash_address="0x$rmdhash$hash4"
    #echo $metahash_address
    rm -f $mh_addr
}

show-private-key () {
get-config
proxy_key=`openssl ec -in $privkey -outform DER 2>/dev/null | xxd -p | tr -d '\r\n'`
echo $proxy_key
}

show-public-key () {
get-config
pubkey_der_16=`openssl ec -in $privkey -pubout -outform DER 2>/dev/null|xxd -p|tr -d '\r\n'`
echo $pubkey_der_16
}

fetch-balance () {
get-config
if [ -z $address ]
then
    echo "Address is mandatory parameter, please specify"
    exit 2
fi
res=`curl -s -X POST --data '{"id":1,"method":"fetch-balance","params":{"address":"'$address'"}}' $torrent_node`
is_json=`echo $res | grep -q '^{.*result.*}$' ; echo $?`
if [  $is_json -ne 0 ]
then
    echo 'not valid json received from server'
else
    echo $res
fi
}


fetch-history () {
get-config
if [ -z $address ]
then
    echo "Address is mandatory parameter, please specify"
    exit 2
fi
res=`curl -s -X POST --data '{"id":1,"method":"fetch-history","params":{"address":"'$address'"}}' $torrent_node`
is_json=`echo $res | grep -q '^{.*result.*}$' ; echo $?`
if [  $is_json -ne 0 ]
then
    echo 'not valid json received from server'
else
    echo $res
fi
}

get-tx () {
get-config
if [ -z $tx_hash ]
then
    echo "tx-hash (transaction hash) is mandatory parameter, please specify"
    exit 2
fi
res=`curl -s -X POST --data '{"id":1,"method":"get-tx","params":{"hash":"'$tx_hash'"}}' $torrent_node`
is_json=`echo $res | grep -q '^{.*result.*}$' ; echo $?`
if [  $is_json -ne 0 ]
then
    echo 'not valid json received from server'
else
    echo $res
fi
}

gen-transaction() {
    function hex_to_endian () {
    endian=''
    i=0
    array=(`echo $1 | grep -o ..`)
    for (( i=${#array[@]}-1 ; i>=0 ; i-- ))
    do
	endian=$endian"${array[i]}"
    done
    }
if [ ! $fee ]
then
    fee=$sizeOfData
fi
for bin in amount fee nonce sizeOfData
do
    bin_value=${!bin}
    if [ -z $bin_value ]
    then
	res=00
    elif [ $bin_value -lt 250 ]
    then
	hex=`printf "%02x" $bin_value`
	res=$hex
    elif [ $bin_value -le 65535 ]
    then
	hex=`printf "%.4x" $bin_value`
	hex_to_endian $hex
	res="fa$endian"
    elif [ $bin_value -gt 65535 ] && [ $bin_value -le 4294967295 ]
    then
	hex=`printf "%.8x" $bin_value `
	hex_to_endian $hex
	res="fb$endian"
    else
	hex=`printf "%.16x" $bin_value `
	hex_to_endian $hex
	res="fc$endian"
    fi
    bin_exp=$bin_exp" $bin->$res "
    bin_data=$bin_data"$res"
done

bin_to=`echo $send_to|sed 's/0x//'`
if [ -z "$data" ]
then
    string_to_sign_hex=$bin_to$bin_data
else
    string_to_sign_hex=$bin_to$bin_data$dataHex
fi
}

prepare-transaction () {
get-config
if [ -z $nonce ]
then
    address=$metahash_address
    balance=$(fetch-balance)
    count_send=`echo $balance|grep -o '"count_spent":.[0-9]*'|cut -d':' -f2`
    nonce=$((count_send+1))
fi
if [ -z $privkey ] || [ ! -f $privkey ]
then
    echo "private key is mandatory option! please specify --privkey=/path/to/private_key "
    exit 2
fi
gen-transaction
to_sign_temp='/tmp/to_sign'
signed_temp='/tmp/signed'
echo $string_to_sign_hex|xxd -r -ps >$to_sign_temp
cat $to_sign_temp | openssl dgst -sha256 -sign $privkey > $signed_temp 2>/dev/null
pubkey_der_16=`openssl ec -in $privkey -pubout -outform DER 2>/dev/null|xxd -p|tr -d '\r\n'`
#echo to_sign_temp=`cat $to_sign_temp` signed_temp=`cat $signed_temp`
openssl dgst -sha256 -verify $pubkey_file -signature $signed_temp $to_sign_temp >/dev/null 2>&1
if [ $? -ne 0 ]
then
    echo Failed to verify signed data, exiting
    exit 2
fi
signed=`cat $signed_temp|xxd -p|tr -d '\r\n'`
json='{"id":1,"method":"mhc_send","params":{"to":"'$send_to'","value":"'$amount'","fee":"'$fee'","nonce":"'$nonce'","data":"'$dataHex'","pubkey":"'$pubkey_der_16'","sign":"'$signed'"}}'
#echo $json
}

send-transaction () {
prepare-transaction
res=`curl -s -X POST --data "$json" $proxy_node`
is_json=`echo $res | grep -q '^{.*result.*}$' ; echo $?`
if [  $is_json -ne 0 ]
then
    echo 'not valid json received from server'
else
    echo $res
fi
}

get-config () {
for arg in "${vars[@]}"
do
    p=`echo $arg|cut -f1 -d=`
    value=`echo $arg|cut -f2 -d=`
    case $p in
	--net)
	net=$value
	;;
	--address)
	address=$value
	;;
	--tx_hash)
	tx_hash=$value
	;;
	--pubkey)
	if [ -f $value ]
	then
	    pubkey_file=$value
	    pubkey=`cat $value`
	    get-address-from-pubkey
	else
	    echo no public key file $value found
	    exit 2
	fi
	;;
	--privkey)
	if [ -f $value ]
	then
	    privkey=$value
	else
	    echo no private key file $value found
	    exit 2
	fi
	;;
	--ecpriv)
	if [ -f $value ]
	then
	    ecpriv=$value
	else
	    echo no private key file $value found
	    exit 2
	fi
	;;
	--amount)
	amount=$value
	;;
	--send_to)
	send_to=$value
	;;
	--nonce)
	nonce=$value
#	echo nonce=$nonce
	;;
	--dataHex)
	dataHex=$value
	data=`echo $dataHex|xxd -r -p`
	#sizeOfData=`echo ${#data}`;
	sizeOfData=`echo $data|awk '{print length}'`
	;;
	--fee)
	fee=$value
	;;
    esac
done

if [ -z $net ]
then
    echo "network is mandatory parameter, please specify"
    exit 2
else
    proxy_node="proxy.net-$net.metahashnetwork.com:9999"
    torrent_node="tor.net-$net.metahashnetwork.com:5795"
fi
}


while :
do
    case "$1" in
    -h | --help)
	 usage
	exit 0
    ;;
    usage)
	usage
	exit 0
    ;;
    generate)
	generate
	exit 0
    ;;
    enc-private-key)
	enc-private-key
	exit 0
    ;;
    dec-private-key)
	dec-private-key
	exit 0
    ;;
    gen-public-key)
	gen-public-key
	exit 0
    ;;
    get-address)
	get-config
	get-address-from-pubkey
	echo "Your Metahash address is $metahash_address"
	exit 0
    ;;
    show-private-key)
	show-private-key
	exit 0
    ;;
    show-public-key)
	show-public-key
	exit 0
    ;;
    fetch-history)
	fetch-history
	exit 0
    ;;
    fetch-balance)
	fetch-balance
	exit 0
    ;;
    get-tx)
	get-tx
	exit 0
    ;;
    gen-tx)
	net=dev
	get-config
	gen-transaction
	echo $string_to_sign_hex
	exit 0
    ;;
    prepare-transaction)
	prepare-transaction
	echo $json
	exit 0
    ;;
    send-transaction)
	send-transaction
	exit 0
    ;;
    -*)
	usage
	exit 1
    ;;
    *)  # No more options
    usage
	exit 1
    ;;
    esac
done
