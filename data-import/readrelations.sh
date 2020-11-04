#!/usr/bin/env bash

mx-run -Ilib CertReader::App::AddCAactors
mx-run -Ilib CertReader::App::AddCArelationships
# Note that we explicitly do not add --disable_certificate_relations_sanity_check to obtain a clean state before starting with the intermediates
# which are even more susceptible to false automated CA actor selection
mx-run -Ilib CertReader::App::AddCertRelationships --root_only --ignore_known_certs --auto_select_cas
mx-run -Ilib CertReader::App::AddCertRelationships --ignore_known_certs --auto_select_cas

