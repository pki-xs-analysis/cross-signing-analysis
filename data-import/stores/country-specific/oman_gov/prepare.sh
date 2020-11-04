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
for f in $(ls intermediates/der)
do
	echo "-- $f"
	openssl x509 -inform der -in intermediates/der/$f -text >> intermediates.0
	echo "---"
done
for f in $(ls intermediates/pem)
do
	echo "-- $f"
	openssl x509 -inform pem -in intermediates/pem/$f -text >> intermediates.0
	echo "---"
done
# intermediates in pkcs7 format
for f in $(ls intermediates/pkcs7)
do
	echo "-- $f"
	openssl pkcs7 -inform der -in intermediates/pkcs7/$f -print_certs >> intermediates.0
	echo "---"
done

