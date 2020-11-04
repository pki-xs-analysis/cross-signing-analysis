echo "" > ca.0
echo "" > intermediates.0

# root certificates
for f in $(ls certs_root)
do
	echo "-- $f"
	openssl x509 -inform der -in certs_root/$f -text >> ca.0
	echo "---"
done

# intermediates der asn.1 format
for f in $(ls certs_intermediate)
do
	echo "-- $f"
	openssl x509 -inform der -in certs_intermediate/$f -text >> intermediates.0
	echo "---"
done
# intermediates in pkcs7 format
for f in $(ls certs_intermediate_cross)
do
	echo "-- $f"
	openssl pkcs7 -inform der -in certs_intermediate_cross/$f -print_certs >> intermediates.0
	echo "---"
done

