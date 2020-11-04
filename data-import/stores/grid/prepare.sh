for f in $(ls igtf-preinstalled-bundle-*.tar.gz)
do
	resultfile=$(basename -s .tar.gz ${f}).ca
	echo -n "" > $resultfile
	echo -e "Extracting certs from $f to $resultfile"
	mkdir ${f}.tmp
	tar -xzf ${f} -C ${f}.tmp
	for file in $(ls ${f}.tmp)
	do
		file_p=${f}.tmp/${file}
		if [ -L $file_p ]; then
			#echo "$file_p is a symlink -> Skipping"
			continue
		fi
		if openssl x509 -noout -in ${file_p} 2>/dev/null; then
			#echo "Adding $file_p to ca file"
			cat ${file_p} >> $resultfile
		else
			#echo "$file_p does *not* contain a certificate -> Skipping"
			:
		fi
	done;
	rm -fr ${f}.tmp
done;

