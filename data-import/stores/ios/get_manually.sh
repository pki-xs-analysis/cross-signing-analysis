#!/bin/bash

echo """
You might want to start the following commands in a separate terminal to search for certs:

while true; do echo "enter CN or similar"; read in; cn=${in// /%20}; echo "retrieving https://crt.sh/?q=${cn}"; curl https://crt.sh/?q=${cn}; done

while true; do echo "enter serial"; read in; cn=${in// /%20}; echo "retrieving https://crt.sh/?q=${cn}"; curl https://crt.sh/?serial=${cn}; done

Press Enter to continue!
"""
read

print_diff() {
	local TMPFILE=$(mktemp)
	openssl x509 -in $2 --text --noout | head -n 11 > $TMPFILE
	sed -i 's/ = /=/g' $TMPFILE # cope with strange formatting in input files ...
	echo -e "\n\n########## diff ##########"
	#git diff --no-index --word-diff -- $1 $TMPFILE
	git diff --no-index --color-words=. -- $1 $TMPFILE
	echo -e "########## diff ##########"
	rm $TMPFILE
}

print_certfile() {
	echo -e "\n\n\n####################"
	openssl x509 -in $1 --text --noout | head -n 11
	echo -e "####################"
}

while getopts ":f:" opt; do
  case ${opt} in
    f)
      INPUTFILE=$OPTARG
      ;;
    :)
      echo "Invalid option: $OPTARG requires an argument" 1>&2
      exit 1
      ;;
  esac
done
shift $((OPTIND -1))

if [ ! -f "$INPUTFILE" ]; then
	echo "Error: $INPUTFILE does not exist." 1>&2
	exit 1
fi

BASEDIR=$(dirname $INPUTFILE)
FILEBASE=$(basename -s .html $INPUTFILE)
TARGETDIR=$BASEDIR/$FILEBASE

echo $TARGETDIR

mkdir -p $TARGETDIR
if [ $(grep -c "Certificate:" $INPUTFILE) = $(grep -c "Not Before:" $INPUTFILE) ]; then
	csplit -f $TARGETDIR/cert_ -b %05d.txt $INPUTFILE /Certificate:/ {*}
elif [ $(grep -c "Version:" $INPUTFILE) = $(grep -c "Public Key Algorithm:" $INPUTFILE) ]; then
	csplit -f $TARGETDIR/cert_ -b %05d.txt $INPUTFILE /Version:/ {*}
else
	echo "ERROR: Please recheck format selection"
fi

for f in $(ls $TARGETDIR/*.txt)
do
	while true;
	do
		clear
		cat $f
		echo "^^^^^^^^^^^  $f  ^^^^^^^^^^^"
		TARGETFILE=$TARGETDIR/$(basename -s .txt ${f}).cert
		if [ -f $TARGETFILE ]; then

			print_certfile $TARGETFILE;
			print_diff $f $TARGETFILE;

			echo -e "\n\n### Already have the cert shown above, enter a new id for crt.sh or s/d (s = skip/keep, d = delete)"
		else
			echo -e "\n### What is the crt.sh certificate id for the given cert? (s = skip)"
		fi

		read userin

	
		if [ $userin = "s" ]; then
			break;
		elif [ $userin = "d" ]; then
			rm $TARGETFILE
		else
			TMPFILE_CERT=$(mktemp)
			curl --fail https://crt.sh/?d=$userin > $TMPFILE_CERT

			print_certfile $TMPFILE_CERT;
			print_diff $f $TMPFILE_CERT;

			echo -e "\n\n### Does the certificate match? (y/N)"
			read userin
			if [ $userin = "y" ]; then
				mv $TMPFILE_CERT $TARGETFILE
				break;
			else
				rm $TARGETFILE
			fi
		fi
	done;
done;

for f in $(ls $TARGETDIR/*.txt)
do
	TARGETFILE=$TARGETDIR/$(basename -s .txt ${f}).cert
	if [ ! -f $TARGETFILE ]; then
		echo "WARNING: No certificate for $f !"
	fi

done
cat $TARGETDIR/*.cert > $BASEDIR/${FILEBASE}.ca

