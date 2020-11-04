echo "" > intermediates.0

for f in $(ls pem)
do
	echo "-- $f"
	openssl x509 -inform pem -in pem/$f -text >> intermediates.0
	echo "---"
done
for f in $(ls der)
do
	echo "-- $f"
	openssl x509 -inform der -in der/$f -text >> intermediates.0
	echo "---"
done

