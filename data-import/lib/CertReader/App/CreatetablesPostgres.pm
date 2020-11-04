package CertReader::App::CreatetablesPostgres;

# application to create our required tables for postgres

use 5.14.1;
use strict;
use warnings;

use Moose;
with 'MooseX::Getopt';
with 'MooseX::Runnable';
with 'CertReader::ORM';

sub run {
	my $self = shift;
	my $postfix = $self->tablepostfix;

	my @commands;

	# fail early
	push(@commands, "CREATE EXTENSION IF NOT EXISTS hstore;");
	push(@commands, "CREATE EXTENSION IF NOT EXISTS ltree;");

	push (@commands, <<END);
CREATE TABLE certificate_$postfix (
 id serial UNIQUE NOT NULL PRIMARY KEY,
 der bytea NOT NULL,
 version integer NOT NULL,
 serial varchar(512) NOT NULL,
 sig_algo varchar(255) NOT NULL,
 not_before timestamp NOT NULL,
 not_after timestamp NOT NULL,
 subject text NOT NULL,
 issuer text NOT NULL,
 key_algo varchar(255) NOT NULL,
 key_mod varchar,
 key_expo bigint,
 key_curve varchar(30),
 key_length integer,
 ca boolean,
 path_len integer,
 subj_alt_name text,
 cert_hash char(32) NOT NULL UNIQUE,
 fingerprint_sha1 char(40) NOT NULL UNIQUE,
 fingerprint_sha256 char(64) NOT NULL UNIQUE,
 fingerprint_sha512 char(128) NOT NULL UNIQUE,
 spki_sha1 char(40),
 spki_sha256 char(64),
 spki_sha512 char(128),
 selfsigned boolean NOT NULL,
 source bit(16) NOT NULL,
 gridtor boolean NOT NULL default 'F',
 first_seen timestamp NOT NULL
);
END
# # Speed up queries on certificate_$postfix
	push (@commands, <<END);
	create index certificate_${postfix}_cacerts on certificate_$postfix (ca) where (ca = True);
END
# push (@commands, <<END);
# create index certificate_${postfix}_keymod on certificate_$postfix (key_mod);
# create index certificate_${postfix}_subject on certificate_$postfix (subject);
# END

	push (@commands, <<END);
CREATE TABLE certificate_validity_by_rootcert_$postfix (
 id serial NOT NULL PRIMARY KEY,
 certificate integer NOT NULL,
 store integer NOT NULL,
 not_before timestamp,
 not_after timestamp,
 issuer_certids varchar,
 FOREIGN KEY(certificate) REFERENCES certificate_$postfix(id),
 FOREIGN KEY(store) REFERENCES root_certs_$postfix(id)
);
END
push (@commands, <<END);
	create index certificate_validity_by_rootcert_${postfix}_certificate on certificate_validity_by_rootcert_$postfix (certificate);
END

push (@commands, <<END);
CREATE TABLE certificate_validity_by_rootcert_state_$postfix (
 certificate integer NOT NULL PRIMARY KEY,
 generated_at timestamp,
 FOREIGN KEY(certificate) REFERENCES certificate_$postfix(id)
);
END

	push (@commands, <<END);
CREATE TABLE crt_sh_certifiate_$postfix (
 crt_sh_id bigint UNIQUE NOT NULL PRIMARY KEY,
 crt_sh_issuer_ca_id integer NOT NULL,
 certificate_id_local integer UNIQUE NOT NULL,
FOREIGN KEY(certificate_id_local) REFERENCES certificate_$postfix(id)
);
END

	push (@commands, <<END);
CREATE TABLE crt_sh_mozilla_onecrl_$postfix (
 entry_id bigserial PRIMARY KEY,
 crt_sh_cert_id bigint,
 crt_sh_issuer_ca_id integer,
 issuer_name bytea,
 last_modified timestamp,
 serial_number bytea,
 created timestamp,
 bug_url text,
 summary text,
 subject_name bytea,
 not_after timestamp
);
END
# "mo_ca_fk" FOREIGN KEY (crt_sh_issuer_ca_id) REFERENCES ca(id)
	push (@commands, <<END);
create index crt_sh_mozilla_onecrl_${postfix}_crtshcertid on crt_sh_mozilla_onecrl_$postfix (crt_sh_cert_id);
END

	push (@commands, <<END);
CREATE TABLE crt_sh_google_revoked_$postfix (
 entry_id bigserial NOT NULL PRIMARY KEY,
 crt_sh_cert_id bigint NOT NULL,
 entry_type text NOT NULL,
UNIQUE (crt_sh_cert_id, entry_type)
);
END
# FOREIGN KEY(crt_sh_cert_id) REFERENCES crt_sh_certifiate_$postfix(crt_sh_id)
	push (@commands, <<END);
create index crt_sh_google_revoked_${postfix}_crtshcertid on crt_sh_google_revoked_$postfix (crt_sh_cert_id);
END

	push (@commands, <<END);
CREATE TABLE crt_sh_microsoft_disallowedcert_$postfix (
 crt_sh_cert_id bigint NOT NULL PRIMARY KEY,
 disallowed_hash bytea
);
END
# FOREIGN KEY(crt_sh_cert_id) REFERENCES crt_sh_certifiate_$postfix(crt_sh_id)

	push (@commands, <<END);
CREATE TABLE crt_sh_crl_revoked_$postfix (
 entry_id bigserial NOT NULL PRIMARY KEY,
 crt_sh_ca_id integer NOT NULL,
 serial_number bytea NOT NULL,
 reason_code smallint,
 revocation_date timestamp,
 last_seen_check_date timestamp,
UNIQUE (crt_sh_ca_id, serial_number)
);
END
    # "crlr_ca_fk" FOREIGN KEY (crt_sh_ca_id) REFERENCES ca(id)
	push (@commands, <<END);
create index crt_sh_crl_revoked_${postfix}_crlr_pk on crt_sh_crl_revoked_$postfix (crt_sh_ca_id, serial_number);
END

	push (@commands, <<END);
CREATE TABLE certificate_validity_$postfix (
 certificate serial UNIQUE NOT NULL PRIMARY KEY REFERENCES certificate_$postfix(id),
 valid boolean NOT NULL default 'F'
);
END


	push (@commands, <<END);
CREATE TABLE seen_$postfix (
	id serial UNIQUE NOT NULL PRIMARY KEY,
	certificate_id integer NOT NULL,
	time timestamp NOT NULL,
FOREIGN KEY(certificate_id) REFERENCES certificate_$postfix(id)
);
END

	push(@commands, "CREATE UNIQUE INDEX seen_".$postfix."_unique_time on seen_$postfix(certificate_id, time);");

	push (@commands, <<END);
CREATE TABLE chains_$postfix (
	id serial UNIQUE NOT NULL PRIMARY KEY,
	chain_hash char(40) UNIQUE,
	certificates integer[]
);
END

	push(@commands, <<END);
create table certificate_extension_$postfix (
 id serial UNIQUE NOT NULL PRIMARY KEY,
 certificate_id integer NOT NULL,
 critical boolean NOT NULL,
 name varchar(255) NOT NULL,
 oid varchar(255) NOT NULL,
 value bytea NOT NULL,
FOREIGN KEY(certificate_id) REFERENCES certificate_$postfix(id)
);
END
# Speed up queries
	push(@commands, <<END);
	create index certificate_extension_${postfix}_certificate_id on certificate_extension_$postfix (certificate_id);
END

	push (@commands, <<END);
CREATE TABLE seen_stats_$postfix (
	id serial unique not null,
	file_name varchar unique not null primary key,
	fields hstore,
	begin_time timestamp,
	end_time timestamp,
	all_lines integer,
	invalid_version integer,
	packet_loss integer,
	established integer,
	all_ports integer,
	https_port integer,
	smtp_port integer,
	with_certs integer,
	with_sni integer,
	with_cert_and_sni integer,
	non_grid integer,
	all_ciphers hstore,
	https_with_certs integer,
	https_with_sni integer,
	https_with_cert_and_sni integer,
	https_resumed integer,
	https_ciphers hstore,
	https_withcert_ciphers hstore,
	https_withcertsni_ciphers hstore,
	smtp_with_certs integer,
	smtp_with_sni integer,
	smtp_with_cert_and_sni integer,
	smtp_resumed integer,
	smtp_ciphers hstore,
	smtp_withcert_ciphers hstore,
	smtp_withcertsni_ciphers hstore,
	resumed integer,
	stapled_ocsp integer,
	dh_param_sizes hstore,
	curves hstore,
	client_curves hstore,
	point_formats hstore,
	client_alpns hstore,
	server_alpns hstore,
	client_exts hstore,
	server_exts hstore,
	client_ciphers hstore,
	versions hstore,
	client_versions hstore,
	supported_versions hstore,
	server_supported_version hstore,
	selected_version hstore,
	psk_key_exchange_modes hstore,
	client_ciphers_all hstore,
	client_extensions_all hstore,
	client_ciphers_and_extensions_all hstore,
	ticket_lifetimes hstore,
	tls_signature hstore
);
END

# this is used for the statistics webpage
	push (@commands, <<'END');
CREATE OR REPLACE FUNCTION key_if_more_than_x_percent(float, float, text) returns text
AS $$ select CASE when $1 > $2 then $3 else 'other' end $$
LANGUAGE SQL;
END

	# TODO we should add NOT NULL to not_before at some point
	# TODO we should add NOT NULL to not_after at some point
	push (@commands, <<END);
CREATE TABLE verify_tree_$postfix (
	id bigserial primary key,
	certificate integer not null,
	store integer not null,
	ca_chain_id bigint not null,
	not_before timestamp,
	not_after timestamp,
	pathlen_allows_issuance boolean,
FOREIGN KEY(certificate) REFERENCES certificate_$postfix(id),
FOREIGN KEY(ca_chain_id) REFERENCES ca_chain_$postfix(id),
FOREIGN KEY(store) REFERENCES root_certs_$postfix(id)
);
END
	# Results in a huge (unique) index table; Uniqueness is already ensured by software
	# unique (certificate, store, path, verify_attime)
# Speed up queries on verify_tree_$postfix
push (@commands, <<END);
create index verify_tree_${postfix}_chain on verify_tree_$postfix (certificate, ca_chain_id);
END
# create index verify_tree_${postfix}_certificate_verify on verify_tree_$postfix (certificate, verify_attime);

	push (@commands, <<END);
CREATE TABLE ca_chain_$postfix (
 id bigserial UNIQUE NOT NULL PRIMARY KEY,
 store integer NOT NULL,
 path ltree NOT NULL,
 chain_len integer NOT NULL,
 leaf_subject_md5 char(32) NOT NULL,
 added_to_db timestamp NOT NULL,
FOREIGN KEY(store) REFERENCES root_certs_$postfix(id)
);
END
push (@commands, <<END);
create index ca_chain_${postfix}_validation on ca_chain_$postfix (store, path, leaf_subject_md5);
create index ca_chain_${postfix}_cert_validation on ca_chain_$postfix (store, leaf_subject_md5);
create index ca_chain_${postfix}_chainlen on ca_chain_$postfix (chain_len);
END

push (@commands, <<END);
CREATE TABLE validation_state_certificate_$postfix (
	cert_id integer primary key,
	verified_at timestamp,
	partial_state_started_at timestamp,
	partial_state_chainlen integer,
	partial_state_rid integer,
	partial_state_cachain bigint,
FOREIGN KEY(cert_id) REFERENCES certificate_$postfix(id)
);
END

push (@commands, <<END);
CREATE TABLE validation_state_rootcert_$postfix (
	rootcert_id integer primary key,
	verified_at timestamp,
	partial_state_started_at timestamp,
	partial_state_chainlen integer,
FOREIGN KEY(rootcert_id) REFERENCES root_certs_$postfix(id)
);
END

push (@commands, <<END);
CREATE TABLE validation_state_rootcert_sub_cert_$postfix (
	id serial primary key,
	rootcert_id integer,
	cert_id integer,
	partial_state_started_at timestamp,
	partial_state_chainlen integer,
	partial_state_cachain bigint,
	partial_state_found_valid_chain boolean,
FOREIGN KEY(rootcert_id) REFERENCES root_certs_$postfix(id),
FOREIGN KEY(cert_id) REFERENCES certificate_$postfix (id)
);
END
push (@commands, <<END);
create index validation_state_rootcert_sub_cert_{$postfix}_rootcertid_certid on validation_state_rootcert_sub_cert_$postfix (rootcert_id, cert_id);
END

push (@commands, <<END);
CREATE TABLE root_certs_$postfix (
	id serial primary key,
	certificate integer unique not null,
	stores text[] not null
);
END

# root_certs_$postfix.stores contains the value used by one rootstore_version_$postfix.tag
push (@commands, <<END);
CREATE TABLE rootstore_version_$postfix (
	id serial primary key,
	rootstore_name varchar(255) NOT NULL,
	tag varchar(255) UNIQUE NOT NULL,
	start_date timestamp,
	end_date timestamp
);
END

push (@commands, <<END);
CREATE TABLE revoked_certs_$postfix (
	id serial primary key,
	certificate integer unique not null,
	flags text[] not null
);
END

push (@commands, <<END);
create table if not exists certs_ports (
id bigserial not null primary key,
certificate_sha1 text not null,
certificate_port int not null);
END

	push(@commands, "CREATE UNIQUE INDEX if not exists certs_ports_unique_shaport on certs_ports(certificate_sha1, certificate_port);");

	# Cross-sign related tables
	push (@commands, <<END);
		CREATE TABLE cross_sign_candidate_$postfix (
			id serial UNIQUE NOT NULL PRIMARY KEY,
			subject text NOT NULL,
			key_mod varchar
		);
END
	# Speed up queries on cross_sign_candidates_$postfix
	push (@commands, <<END);
		create index cross_sign_candidate_${postfix}_subject on cross_sign_candidate_$postfix (md5(subject));
		create index cross_sign_candidate_${postfix}_keymod on cross_sign_candidate_$postfix (md5(key_mod));
END

	push (@commands, <<END);
		CREATE TABLE csc_cert_$postfix (
			id serial UNIQUE NOT NULL PRIMARY KEY,
			csc_id integer NOT NULL,
			cert_id integer NOT NULL,
			from_subj_alt_ext boolean,
			FOREIGN KEY(csc_id) REFERENCES cross_sign_candidate_$postfix(id),
			FOREIGN KEY(cert_id) REFERENCES certificate_$postfix(id)
		);
END
	# Speed up queries
	push (@commands, <<END);
		create index csc_cert_${postfix}_csc_id on csc_cert_$postfix (csc_id);
		create index csc_cert_${postfix}_cert_id on csc_cert_$postfix (cert_id);
END

push (@commands, <<END);
		CREATE TABLE csc_metadata_$postfix (
			csc_id integer PRIMARY KEY,
			evaluated_at timestamp,
			any_cert_valid boolean,
			cs_valid boolean,
			with_root boolean,
			with_revoked_root boolean,
			cs_rootcert boolean,
			cs_intermediate boolean,
			cs_leaf boolean,
			cs_leafmix boolean,
			cs_multisignalgs boolean,
			cs_extstorecover boolean,
			cs_alternpaths boolean,
			cs_bootstrapping boolean,
			cs_ca_intern_singlecert boolean,
			cs_ca_intern_multicert boolean,
			cs_ca_intern_multicert_oneca boolean,
			cs_ca_intern_multicas boolean,
			cs_ca_extern_singlecert boolean,
			cs_ca_extern_multicert boolean,
			cs_ca_extern_multicert_oneca boolean,
			cs_ca_extern_multicas boolean,
			cs_leaf_singleca boolean,
			cs_leaf_multicas boolean,
			cs_leaf_singlecert_oneca boolean,
			cs_leaf_multicert_oneca boolean,
			validity_gap boolean,
			sub_groups integer,
			largest_validcertcnt_subgroups integer,
			FOREIGN KEY(csc_id) REFERENCES cross_sign_candidate_$postfix(id)
		);
END

push (@commands, <<END);
		CREATE TABLE csc_evalstate_$postfix (
			csc_id serial UNIQUE NOT NULL PRIMARY KEY,
			evaluated_at timestamp,
			FOREIGN KEY(csc_id) REFERENCES cross_sign_candidate_$postfix(id)
		);
END

	push (@commands, <<END);
		CREATE TABLE ca_actor_$postfix (
			id serial UNIQUE NOT NULL PRIMARY KEY,
			name text NOT NULL UNIQUE
		);
END
	push (@commands, <<END);
		CREATE TABLE certificate_relation_$postfix (
			id serial UNIQUE NOT NULL PRIMARY KEY,
			certificate_id integer NOT NULL UNIQUE,
			owner_id integer NOT NULL,
			FOREIGN KEY(certificate_id) REFERENCES certificate_$postfix(id),
			FOREIGN KEY(owner_id) REFERENCES ca_actor_$postfix(id)
		);
END
	push (@commands, <<END);
		CREATE TYPE ca_relation_type AS ENUM ('owned_by', 'reseller_of');
END
	push (@commands, <<END);
		CREATE TABLE ca_relation_$postfix (
			id serial UNIQUE NOT NULL PRIMARY KEY,
			ca_id integer NOT NULL,
			related_ca_id integer NOT NULL,
			type ca_relation_type NOT NULL,
			not_before timestamp NOT NULL,
			FOREIGN KEY(ca_id) REFERENCES ca_actor_$postfix(id),
			FOREIGN KEY(related_ca_id) REFERENCES ca_actor_$postfix(id)
		);
END

	# Execute commands
	for my $command ( @commands ) {
		say "Executing $command";
		my $sth = $self->db->dbh->prepare($command);
		$sth->execute;
	}
}

1;
