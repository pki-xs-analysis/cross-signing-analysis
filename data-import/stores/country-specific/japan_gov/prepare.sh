echo "" > ca.0
#echo "" > intermediates.0

# root certificates
for f in $(ls certs_root)
do
	echo "-- $f"
	openssl x509 -inform der -in certs_root/$f -text >> ca.0
	echo "---"
done

