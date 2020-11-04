echo "" > ca.0
#echo "" > intermediates.0

# root certificates
for f in $(ls certs_root)
do
	echo "-- $f"
	base64 -d certs_root/$f | openssl x509 -inform der -text >> ca.0
	echo "---"
done

