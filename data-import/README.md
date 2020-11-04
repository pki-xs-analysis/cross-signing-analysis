# Setup

* Read install-prereqs.sh.
* Do steps in install-prereqs.sh
* Run install-prereqs.sh

Afterwards, try createTestEnvironment.sh. If it works, everything is fine.

CreateTestEnvironment shows how to create a suitable environment and how to
load certificate/connection files into the database.

# Update existing (notary) database

Disclaimer 1: This manual may be outdated. Check the git log since the last changes to this
README. You especially want to have a look for changes to `CreatetablesPostgres.pm`:
```bash
git log -p lib/CertReader/App/CreatetablesPostgres.pm
```

Disclaimer 2: Be sure to have a backup of your database, just in case

### Update repo

```bash
git pull
```

### Get required perl packets (some may be missing)

```bash
./data-import/install-prereqs.sh
```

### Reset validation system

**Double check if this is needed as it will require a lot of work to revalidate**

```bash
psql -p 7779 -d notary -c 'DELETE FROM root_certs_full';
psql -p 7779 -d notary -c 'ALTER SEQUENCE root_certs_full_id_seq RESTART WITH 1'; # optional
psql -p 7779 -d notary -c 'DELETE FROM verify_tree_full';
psql -p 7779 -d notary -c 'ALTER SEQUENCE verify_tree_full_id_seq RESTART WITH 1'; # optional
# Note: reset of certificate_full valid field not required as it will be dropped in the next step
```

### Update database structure (not needed if setting up a fresh database)

```bash
# Add index for fast access to CA certificates
psql -p 7779 -d notary -c 'CREATE INDEX certificate_full_cacerts ON certificate_full (ca) where (ca = True);'

# drop valid column and introduce verify_attime
psql -p 7779 -d notary -c 'ALTER TABLE certificate_full DROP COLUMN valid';
psql -p 7779 -d notary -c 'ALTER TABLE verify_tree_full ADD COLUMN verify_attime timestamp not null';
psql -p 7779 -d notary -c 'create index verify_tree_${postfix}_certificate_verify on verify_tree_$postfix (certificate, verify_attime);'
# Add table for revoked certificates
psql -p 7779 -d notary -c 'CREATE TABLE revoked_certs_$postfix ( id serial primary key, certificate integer unique not null, flags text[] not null );'

# Updates for verify_tree
psql -p 7779 -d notary -c 'ALTER TABLE verify_tree_full ADD COLUMN not_before timestamp;'
psql -p 7779 -d notary -c 'ALTER TABLE verify_tree_full ADD COLUMN not_after timestamp;'
psql -p 7779 -d notary -c 'ALTER TABLE verify_tree_full ADD COLUMN pathlen_allows_issuance boolean;'

# Add tables for use of crt.sh information
psql -p 7779 -d notary -c 'CREATE TABLE crt_sh_certifiate_full ( crt_sh_id bigint UNIQUE NOT NULL PRIMARY KEY, crt_sh_issuer_ca_id integer NOT NULL, certificate_id_local integer UNIQUE NOT NULL, FOREIGN KEY(certificate_id_local) REFERENCES certificate_full(id) );'
psql -p 7779 -d notary -c 'CREATE TABLE crt_sh_mozilla_onecrl_full ( entry_id bigserial PRIMARY KEY, crt_sh_cert_id bigint, crt_sh_issuer_ca_id integer, issuer_name bytea, last_modified timestamp, serial_number bytea, created timestamp, bug_url text, summary text, subject_name bytea, not_after timestamp );'
psql -p 7779 -d notary -c 'create index crt_sh_mozilla_onecrl_full_crtshcertid on crt_sh_mozilla_onecrl_full (crt_sh_cert_id);'
psql -p 7779 -d notary -c 'CREATE TABLE crt_sh_google_revoked_full ( entry_id bigserial NOT NULL PRIMARY KEY, crt_sh_cert_id bigint NOT NULL, entry_type text NOT NULL, UNIQUE (crt_sh_cert_id, entry_type) );'
psql -p 7779 -d notary -c 'create index crt_sh_google_revoked_full_crtshcertid on crt_sh_google_revoked_full (crt_sh_cert_id);'
psql -p 7779 -d notary -c 'CREATE TABLE crt_sh_microsoft_disallowedcert_full ( crt_sh_cert_id bigint NOT NULL PRIMARY KEY, disallowed_hash bytea );'
psql -p 7779 -d notary -c 'CREATE TABLE crt_sh_crl_revoked_full ( entry_id bigserial NOT NULL PRIMARY KEY, crt_sh_ca_id integer NOT NULL, serial_number bytea NOT NULL, reason_code smallint, revocation_date timestamp, last_seen_check_date timestamp, UNIQUE (crt_sh_ca_id, serial_number) );'

# Add table ca_chain
psql -p 7779 -d notary -c 'CREATE TABLE ca_chain_full ( id bigserial UNIQUE NOT NULL PRIMARY KEY, store integer NOT NULL, path ltree NOT NULL, chain_len integer NOT NULL, leaf_subject_md5 char(32) NOT NULL, FOREIGN KEY(store) REFERENCES root_certs_full(id) );'
psql -p 7779 -d notary -c 'create index ca_chain_full_validation on ca_chain_full (store, path, leaf_subject_md5);'
psql -p 7779 -d notary -c 'create index ca_chain_full_cert_validation on ca_chain_full (store, leaf_subject_md5);'
psql -p 7779 -d notary -c 'create index ca_chain_full_chainlen on ca_chain_full (chain_len);'

# Prepare for keeping track of validation status
psql -p 7779 -d notary -c "ALTER TABLE ca_chain_full ADD COLUMN added_to_db timestamp NOT NULL DEFAULT '2020-08-19 00:00:00';"
psql -p 7779 -d notary -c 'CREATE TABLE validation_state_certificate_full ( cert_id integer primary key, verified_at timestamp NOT NULL, FOREIGN KEY(cert_id) REFERENCES certificate_full(id) );'
# Updated state tracking
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_certificate_full ALTER COLUMN verified_at DROP NOT NULL;'
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_certificate_full ADD COLUMN partial_state_started_at timestamp;'
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_certificate_full ADD COLUMN partial_state_chainlen integer;'
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_certificate_full ADD COLUMN partial_state_rid integer;'
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_certificate_full ADD COLUMN partial_state_cachain bigint;'

# New schema for verify tree
psql -p 7779 -d notary -c 'CREATE TABLE verify_tree_full ( id bigserial primary key, certificate integer not null, store integer not null, ca_chain_id bigint not null, not_before timestamp, not_after timestamp, pathlen_allows_issuance boolean, FOREIGN KEY(certificate) REFERENCES certificate_full(id), FOREIGN KEY(ca_chain_id) REFERENCES ca_chain_full(id), FOREIGN KEY(store) REFERENCES root_certs_full(id) );'
psql -p 7779 -d notary -c 'create index verify_tree_full_chain on verify_tree_full (certificate, ca_chain_id);'

# state tracking for EvalCrosssign
psql -p 7779 -d notary -c 'CREATE TABLE csc_evalstate_full ( csc_id serial UNIQUE NOT NULL PRIMARY KEY, evaluated_at timestamp, FOREIGN KEY(csc_id) REFERENCES cross_sign_candidate_full(id) );'
psql -p 7779 -d notary -c 'CREATE TABLE certificate_validity_by_rootcert_full ( id serial NOT NULL PRIMARY KEY, certificate integer NOT NULL, store integer NOT NULL, not_before timestamp, not_after timestamp, FOREIGN KEY(certificate) REFERENCES certificate_full(id), FOREIGN KEY(store) REFERENCES root_certs_full(id));'
psql -p 7779 -d notary -c 'create index certificate_validity_by_rootcert_full_certificate on certificate_validity_by_rootcert_full (certificate);'
psql -p 7779 -d notary -c 'CREATE TABLE certificate_validity_by_rootcert_state_full ( certificate integer NOT NULL PRIMARY KEY, generated_at timestamp, FOREIGN KEY(certificate) REFERENCES certificate_full(id));'
psql -p 7779 -d notary -c 'ALTER TABLE certificate_validity_by_rootcert_full ADD COLUMN issuer_certids varchar;'

# Meta information for rootstore tags
psql -p 7779 -d notary -c 'CREATE TABLE rootstore_version_full ( id serial primary key, rootstore_name varchar(255) NOT NULL, tag varchar(255) UNIQUE NOT NULL, start_date timestamp, end_date timestamp );'

# Meta information for found csc_ids
psql -p 7779 -d notary -c 'CREATE TABLE csc_metadata_full ( csc_id integer PRIMARY KEY, evaluated_at timestamp, any_cert_valid boolean, cs_valid boolean, with_root boolean, with_revoked_root boolean, cs_rootcert boolean, cs_intermediate boolean, cs_leaf boolean, cs_leafmix boolean, cs_multisignalgs boolean, cs_expanding_store boolean, cs_expanding_time boolean, cs_alternpaths boolean, cs_bootstrapping boolean, cs_ca_intern_singlecert boolean, cs_ca_intern_multicert boolean, cs_ca_intern_multicert_oneca boolean, cs_ca_intern_multicas boolean, cs_ca_extern_singlecert boolean, cs_ca_extern_multicert boolean, cs_ca_extern_multicert_oneca boolean, cs_ca_extern_multicas boolean, cs_leaf_singleca boolean, cs_leaf_multicas boolean, cs_leaf_singlecert_oneca boolean, cs_leaf_multicert_oneca boolean, validity_gap boolean, sub_groups integer, largest_validcertcnt_subgroups integer, FOREIGN KEY(csc_id) REFERENCES cross_sign_candidate_full(id) );'

# Prepare for keeping track of ca_chain generation
psql -p 7779 -d notary -c 'CREATE TABLE validation_state_rootcert_full ( rootcert_id integer primary key, verified_at timestamp, partial_state_started_at timestamp, partial_state_chainlen integer, FOREIGN KEY(rootcert_id) REFERENCES root_certs_full(id) );'
psql -p 7779 -d notary -c 'CREATE TABLE validation_state_rootcert_sub_cert_full ( id serial primary key, rootcert_id integer, cert_id integer, partial_state_started_at timestamp, partial_state_chainlen integer, FOREIGN KEY(rootcert_id) REFERENCES root_certs_full(id), FOREIGN KEY(cert_id) REFERENCES certificate_full (id) );'
psql -p 7779 -d notary -c 'create index validation_state_rootcert_sub_cert_full_rootcertid_certid on validation_state_rootcert_sub_cert_full (rootcert_id, cert_id);'
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_rootcert_sub_cert_full ADD COLUMN partial_state_cachain bigint;'
psql -p 7779 -d notary -c 'ALTER TABLE validation_state_rootcert_sub_cert_full ADD COLUMN partial_state_found_valid_chain boolean;'
```


# Usage (Loading data into database and running evaluation)

### Load current root stores and revocations

```bash
./readroots.sh
./readrevocations.sh
```

### Load crt.sh-like structured information (if available)

```bash
./read_crt_sh.sh
```

### Validate CA certificates (creates entries in verify_tree_full)

Note: If your database contains old verify_tree entries, consider to add the option ```--update_known_paths```
to the VerifyCerts commands (see ```--help```).

```bash
time nice mx-run -Ilib CertReader::App::VerifyCerts --attime_label validity_any_day --mode OpenSSLCAs --nworker 20
```

Validation of all, i.e., CA and non-CA, certificates can be triggered with the following command (placed in a comment on purpose; see below).
However, that may not be required, but will require a lot of time, hence, rather skip it if not needed.
*Still, a full eval that also considers leaf certificates will require this information*
```bash
time nice mx-run -Ilib CertReader::App::VerifyCerts --mode OpenSSLall --nworker 24 --attime_label validity_any_day
```

#### See current state of validation

When populating intermediates (i.e., when generating entries for table ca_chain):
```bash
# To get the chainlen status per rootcert
# psql -p 7779 -d notary -c 'select store, max(chain_len) from ca_chain_full where store in (134,143,147,165,167,168,205,248,249,413,43,56,65) group by store order by store;'
psql -p 7779 -d notary -c 'select clock_timestamp(), s.*, c.subject from validation_state_rootcert_full as s join root_certs_full as r on s.rootcert_id = r.id join certificate_full as c on r.certificate = c.id  where verified_at is Null order by rootcert_id; select clock_timestamp(), max(id) as ca_chain_id_max from ca_chain_full;'
# To get the certificate status per rootcert
psql -p 7779 -d notary -c 'select clock_timestamp(), rootcert_id, partial_state_chainlen, count(*) as cnt from validation_state_rootcert_sub_cert_full where rootcert_id in (select rootcert_id from validation_state_rootcert_full where verified_at is Null) group by rootcert_id, partial_state_chainlen order by rootcert_id, partial_state_chainlen asc;'
```

When evaluating leaf certificates (i.e., generating entries for table verify_tree)
```bash
psql -p 7779 -d notary -c 'select clock_timestamp(), verified_at is not Null as is_fully_verified, partial_state_chainlen, count(*)  from validation_state_certificate_full group by is_fully_verified, partial_state_chainlen order by is_fully_verified desc, partial_state_chainlen desc;'
```

#### Troubeshooting and Error-Recovery

**Outdated: The (partial) validation state is automatically tracked within the database**

After any error, you do not want to restart from scratch but resume the work.
Get a log of the validation script output (see `./logparser_validationstate.py --help` for a way to copy the data from a screen session) and
feed the output of the validation script to `./logparser_validationstate.py` as follows:
```bash
./logparser_validationstate.py -f <log>
```
The script will provide you with the correct certificate id for a restart the valudation script using the following option (carefully read any warning or error messages!)
```bash
--start_with_certid <certid>
```

### Validity Table (Optional)

**Optionally**, we can create a table for quick-access to information if a certificate is or has been valid at any time
```bash
time nice mx-run -Ilib CertReader::App::UpdateValidityTable --nworker 24
```

### Provide information on relationships between certificates and CAs and among CAs

A deep-dive evaluation and automated detailed grouping of cross-signs requires information on the owner CA of root and intermediate certificates.
*Warning: This only considers valid certificates. Thus, it depends on the completion of the validation with CertReader::App::VerifyCerts*

*Note: This is a half-automated process which might require considerable manual effort depending on the amount of yet unknown CAs*
```bash
./readrelations.sh
```

### Run the eval

```bash
# Create tables with all observed (subject, key_mod) tuples and corresponding certs
time mx-run -Ilib CertReader::App::EvalCrosssign --only_database_update --nworker 20
# Run the actual eval: Find cross-sing certificates, ...
time mx-run -Ilib CertReader::App::EvalCrosssign --skip_database_update --nworker 20 --verbosity 1
```
