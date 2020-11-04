#!/usr/bin/env bash

mx-run -Ilib CertReader::App::ImportCrtShCertificates crt_sh/certificate_ca-certs-only.table
mx-run -Ilib CertReader::App::ImportCrtShCertificates crt_sh/mozilla_onecrl_certs.table
mx-run -Ilib CertReader::App::ImportCrtShCertificates crt_sh/google_revoked_certs.table
mx-run -Ilib CertReader::App::ImportCrtShCertificates crt_sh/microsoft_disallowedcert_certs.table
