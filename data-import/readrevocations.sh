#!/usr/bin/env bash

# # legacy
# mx-run -Ilib CertReader::App::ImportRevocations --tag mozilla
# mx-run -Ilib CertReader::App::ImportRevocations --tag microsoft
# mx-run -Ilib CertReader::App::ImportRevocations --tag android
# mx-run -Ilib CertReader::App::ImportRevocations --tag grid-igtf-classic
# mx-run -Ilib CertReader::App::ImportRevocations --tag grid-igtf-iota
# mx-run -Ilib CertReader::App::ImportRevocations --tag grid-igtf-mics
# mx-run -Ilib CertReader::App::ImportRevocations --tag grid-igtf-slcs

set -e

mx-run -Ilib CertReader::App::ImportCrtShRevocationsMozillaOneCRL crt_sh/mozilla_onecrl.table
mx-run -Ilib CertReader::App::ImportCrtShRevocationsGoogle crt_sh/google_revoked.table
mx-run -Ilib CertReader::App::ImportCrtShRevocationsMicrosoft crt_sh/microsoft_disallowedcert.table
for crl_table_file in $(ls crt_sh/crl_revoked);
do
    if [ -s crt_sh/crl_revoked/$crl_table_file ]
    then
        echo "Importing $crl_table_file"
        mx-run -Ilib CertReader::App::ImportCrtShRevocationsCRL crt_sh/crl_revoked/$crl_table_file
    fi
done;
