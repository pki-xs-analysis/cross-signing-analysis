echo "" > intermediates.0

find pem -type f -exec echo "-- $f" \; -exec openssl x509 -inform pem -in {} -text >> intermediates.0 \; -exec echo "---" \;
find pem_list -type f -exec echo "-- $f" \; -exec cat {} >> intermediates.0 \; -exec echo "---" \;
find der -type f -exec echo "-- $f" \; -exec openssl x509 -inform der -in {} -text >> intermediates.0 \; -exec echo "---" \;

