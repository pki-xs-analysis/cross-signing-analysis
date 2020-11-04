
for v in {0..92};
do
	for t in classic iota mics slcs;
	do
		BASE=igtf-preinstalled-bundle-${t}-1.${v}
		ARCHIVE=${BASE}.tar.gz
		if [ $v -gt 59 ]
		then
			URL=https://dl.igtf.net/distribution/igtf/1.${v}/accredited/$ARCHIVE
		else
			URL=https://dl.igtf.net/distribution/igtf/Outdated/1.${v}/accredited/$ARCHIVE
		fi
		echo -e "\nGET $BASE"
		wget $URL
		#if [ $? -eq 0 ]
		#then
		#	mkdir $BASE
		#	tar -xzf $ARCHIVE -C $BASE
		#	rm -f $ARCHIVE
		#fi
	done;
done;

