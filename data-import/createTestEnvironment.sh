#!/usr/bin/env bash


initdb postgres
# If you do not trust all users on the server you can now modify the file postgres/pg_hba.conf
perl -pi.bak -E "s/#port =.*/port = 7779/;" postgres/postgresql.conf
# You should consider to optimize the postgresql config to your system settings, e.g., using https://pgtune.leopard.in.ua/
pg_ctl start -D postgres -l serverlog
sleep 2
createdb -p 7779 notary
mx-run -Ilib CertReader::App::CreatetablesPostgres
source readroots.sh

# Ok, from here it is test-code. So, instead of loading this, load your own data.
# Both, readcertmap and readseen are parallelizable - they just dump data to the DB.
# They might show errors when they encounter conflicts, but they re-try. If they can
# not continue for some reason, they will exit with an abnormal error code, not
# just complain.
#
# Usual ways to run are something along the lines of:
#
# find ./ -name “ssl_certmap*.log.gz” -print0 | xargs -0 -P32 -n5 mx-run -Ilib CertReader::App::Readcertmap --source [freely chosen sourcenumber that is probably not important for our paper; used to distinguish between sites at ICSI]
# find ./ -name “ssl_connections*.log.gz” -print0 | xargs -0 -P32 -n5 mx-run -Ilib CertReader::App::Readseen

# old format
mx-run -Ilib CertReader::App::Readcertmap --source 1 testdata/ssl_certmap_old.log.xz
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections_old.log.xz

# new format:
mx-run -Ilib CertReader::App::Readcertmap --source 1 testdata/ssl_certmap.log.xz
# and as gz
mx-run -Ilib CertReader::App::Readcertmap --source 1 testdata/ssl_certmap_copy.log.gz
mx-run -Ilib CertReader::App::Readcertmap --source 1 testdata/ssl_certmap_ritter.vg.log.xz
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections.log.xz

# json files...
# new format:
mx-run -Ilib CertReader::App::Readcertmap --source 1 testdata/ssl_certmap.json.xz
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections.json.xz

# tls 1.3 connection
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections_13.log.xz

# sslv3 connection
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections_v3.log.xz

# paper-specific testdata
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections_13_versions.log.xz
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections_ct.log.xz
mx-run -Ilib CertReader::App::Readseen testdata/ssl_connections_13_new.log

# censys testdata
mx-run -Ilib CertReader::App::Readcertmap --source 2 --zgrab_format testdata/s5isqchf8sqzf0pg-443-https-tls-alexa_top1mil-20180527T100002-zgrab-results_stripped.json.lz4

# These are the scripts that validate the certificates. They are, in their current
# version not parallelizable. If their speed turns out to be problematic, we can
# try to change that.
time mx-run -Ilib CertReader::App::VerifyCerts --mode OpenSSLCAs
time mx-run -Ilib CertReader::App::VerifyCerts --mode OpenSSLAll

# Try re-reading one of the seen-stats files.
echo "CREATE TABLE seen_stats_new as ( select * from seen_stats_full where 'F' );" | psql -p 7779 notary
mx-run -Ilib CertReader::App::ImportStatistics --tablename seen_stats_new testdata/ssl_connections_ct.log.statistics
