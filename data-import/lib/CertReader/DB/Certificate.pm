package CertReader::DB::Certificate;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;
use Crypt::OpenSSL::X509;

use Carp;

use Array::Utils qw(:all);
use Date::Format;

use CertReader::DB::VerifyTree;
use CertReader::DB::RootCerts;
use CertReader::DB::RevokedCerts;
use CertReader::DB::CertificateRelation;
use CertReader::DB::CArelation;
use CertReader::DB::CrtShCertificate;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'certificate',
	columns => [
		id => { type => 'serial', },
		der => { type => 'bytea', not_null => 1, },
		version => { type => 'integer', not_null => 1, },
		serial => { type => 'varchar', not_null => 1, length => 512 },
		sig_algo => { type => 'varchar', not_null => 1, length => 255 },
		issuer =>  { type => 'text', not_null => 1, },
		#not_before => { type => 'timestamp', not_null => 1 },
		#not_after => { type => 'timestamp', not_null => 1 },
		#yep. simply lie...
		first_seen => { type => 'timestamp', not_null => 1},
		not_before => { type => 'varchar', not_null => 1, length => 255 },
		not_after => { type => 'varchar', not_null => 1, length => 255 },
		subject => { type => 'text', not_null => 1, },
		key_algo => { type => 'varchar', not_null => 1, length => 255 },
		key_mod => { type => 'varchar'  },
		key_expo =>  { type => 'integer'  },
		key_curve => { type => 'varchar' }, # ec curve
		key_length =>  { type => 'integer' },
		ca => { type => 'boolean' },
		path_len => { type => 'integer' },
		gridtor => { type => 'boolean', not_null => 1, default => 0},
		subj_alt_name => { type => 'text' },
		cert_hash => { type => 'char', length => 32 },
		fingerprint_sha1 => { type => 'char', length => 40 },
		fingerprint_sha256 => { type => 'char', length => 64 },
		fingerprint_sha512 => { type => 'char', length => 128 },
		spki_sha1 => { type => 'char', length => 40 },
		spki_sha256 => { type => 'char', length => 64 },
		spki_sha512 => { type => 'char', length => 128 },
		selfsigned => { type => 'boolean', not_null => 1 },
		source => { type => 'bitfield', bits => 16, not_null => 1 },
		# valid => { type => 'bitfield', not_null=> 1, default=>0, bits=> 1024 },
       	],
	pk_columns => 'id',
	unique_keys => [ qw/cert_hash fingerprint_sha1 fingerprint_sha256 fingerprint_sha512/ ],

	# TODO Performance issue
	#
	# Introduces a lot of runtime and maintainability overhead considering the
	# new attime support. If this functionality is really desired, one would
	# be probably better off by implementing it with sql queries to the
	# verify_tree_full instead of maintaining another table which essentially
	# stores the same information.
	# Note that using the relationships functionality of Rose::DB is rather a
	# bad idea if the attime is managed in a column, as Rose::DB will then
	# always fetch all entries for a certificate. Hence, we always have to
	# iterate over this full list to filter out the relevant entry based on
	# the attime. Hence, for efficiency, a corresponding entry should not be
	# fetched via the relationships/foreign key functionality of Rose::DB but
	# separately to leverage the knowledge that there is only one attime valid
	# at a specific run of the scripts.
	#
	# relationships => [
	# 	validities => {
	# 		type => 'one to many',
	# 		class => 'CertReader::DB::CertificateValidity',
	# 		column_map => { id => 'certificate' },
	# 	},
	# ],
);

sub get_crtsh_certificate {
	my $self = shift;

	if (defined($self->{'crtsh_certificate'})) {
		return $self->{'crtsh_certificate'};
	}

	my $crtshcert = CertReader::DB::CrtShCertificate->new(certificate_id_local => $self->id);
	if ($crtshcert->load(use_key => 'certificate_id_local', speculative => 1)) {
		;
	} else {
		$crtshcert = undef;
	}

	$self->{'crtsh_certificate'} = $crtshcert;
	return $crtshcert;
}

sub get_crtsh_id {
	my $self = shift;

	my $crtshcert = $self->get_crtsh_certificate;
	if (defined $crtshcert) {
		return $crtshcert->crt_sh_id;
	} else {
		return undef;
	}
}

sub is_valid {
	# RETURN 0 = invalid, 1 = valid, 2 = rootcert, 3 = removed from some but still in some stores, -1 = removed rootcert

	# TODO The current implementation fails to correctly assign revoked certs to 3 or -1:
	# Since we started to add *all* and not only the recent rootstores to the rootstore database,
	# all revoked certificates will be flagged as 3. To determine state -1, we must actively check if it
	# was revoked in *all* root stores. Previously, we could just rely on that a revoked certificate that is currently not
	# in any root store must have been revoked from all, which does not work anymore when having not only recent
	# rootstores in the roots table.

	my ($self, $postfix, $attime) = @_;

	$attime = "any" if !defined($attime);
	$self->{'is_valid'} = {} if !defined($self->{'is_valid'});

	if ( defined($self->{'is_valid'}{$attime}) ) {
		return $self->{'is_valid'}{$attime};
	}

	my $ret = 0;
	my $sql;
	if ($attime eq "any") {
		$sql = "select * from verify_tree_$postfix where certificate = $self->{id} LIMIT 1;";
	} else {
		$sql = "select * from verify_tree_$postfix where certificate = $self->{id} and verify_attime = $attime LIMIT 1;";
	}
	my $vts = CertReader::DB::VerifyTree::Manager->get_verifypaths_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => $sql,
	);
	if (scalar @$vts) {
		$ret = 1;
	}

	if ($ret == 0) {
		if ($self->is_root_cert) {
			$ret = 2;
		}
	}

	if ($ret == 0 or $ret == 2) {
		if ($self->is_revoked_cert) {
			if ($ret == 2) {
				$ret = 3;
			} else {
				$ret = -1;
			}
		}
	}

	$self->{'is_valid'}{$attime} = $ret;
	return $ret;

}

sub is_root_cert {
	my $self = shift;

	my $ret = 0;
	if ($self->get_root_cert) {
		$ret = 1;
	}

	return $ret;
}

sub get_root_cert {
	my $self = shift;
	if (!defined($self->{'root_cert'})) {

		if (defined $self->{'rootcert_cache'}) {
			for my $storeid (keys %{$self->{'rootcert_cache'}}) {
				my $rootcert = $self->{'rootcert_cache'}->{$storeid};
				if ($rootcert->certificate == $self->id) {
					$self->{'root_cert'} = $rootcert;
					last;
				}
			}
		}

		if (!defined($self->{'root_cert'})) {
			$self->{'root_cert'} = CertReader::DB::RootCerts->cert_to_rootcert($self);
		}
	}
	return $self->{'root_cert'};
}

sub get_onecrl_revocation_info {
	# returns
	#  An array with revocation dates if revoked
	#  0 if we know the crt.sh certid but no revocation is found
	#  undef if we do not have a crt.sh cert for this certificate
	my $self = shift;

	my $revocation_dates;
	my $crtsh_cert = $self->get_crtsh_certificate;
	if (defined $crtsh_cert){

		my $sql = "select onecrl.* from crt_sh_mozilla_onecrl_full as onecrl where $crtsh_cert->{crt_sh_id} = crt_sh_cert_id or (crt_sh_issuer_ca_id = $crtsh_cert->{crt_sh_issuer_ca_id} and lower('$self->{serial}') = substr(onecrl.serial_number::text, 3));";
		my $onecrl_entries = CertReader::DB::CrtShRevocationData::MozillaOneCRL::Manager->get_objects_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
			);
		while (my $onecrl_entry = $onecrl_entries->next) {
			$revocation_dates //= [];
			my $date = defined $onecrl_entry->created ? $onecrl_entry->created : "date_unknown";
			push(@$revocation_dates, $date);
		}

		$revocation_dates //= 0;
	}

	return $revocation_dates;
}

sub get_google_revocation_info {
	# returns
	#  An array with revocation entry types if revoked
	#  0 if we know the crt.sh certid but no revocation is found
	#  undef if we do not have a crt.sh cert for this certificate
	my $self = shift;

	my $revocation_reasons;
	my $crtsh_cert = $self->get_crtsh_certificate;
	if (defined $crtsh_cert) {
		my $sql = "select * from crt_sh_google_revoked_full where crt_sh_cert_id = $crtsh_cert->{crt_sh_id};";
		my $google_revocation_entries = CertReader::DB::CrtShRevocationData::GoogleRevoked::Manager->get_objects_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
			);

		while (my $google_revocation_entry = $google_revocation_entries->next) {
			$revocation_reasons //= [];
			push (@$revocation_reasons, $google_revocation_entry->entry_type);
		}

		$revocation_reasons //= 0;
	}

	return $revocation_reasons;
}

sub is_microsoft_revoked {
	# returns
	#  1 if revoked by microsoft
	#  0 if we know the crt.sh certid but no revocation is found
	#  undef if we do not have a crt.sh cert for this certificate
	my $self = shift;

	my $res = undef;
	my $crtsh_cert = $self->get_crtsh_certificate;
	if (defined $crtsh_cert){
		my $ms_revocation_entry = CertReader::DB::CrtShRevocationData::MicrosoftDisallowed->new(crt_sh_cert_id => $crtsh_cert->crt_sh_id);
		if ($ms_revocation_entry->load(speculative => 1)) {
			$res = 1;
		} else {
			$res = 0;
		}
	}

	return $res;
}

sub get_crl_revocation_dates {
	# returns
	#  An array with revocation dates if revoked
	#  0 if we know the crt.sh certid but no revocation is found
	#  undef if we do not have a crt.sh cert for this certificate
	my $self = shift;

	my $revocation_dates;
	my $crtsh_cert = $self->get_crtsh_certificate;
	if (defined $crtsh_cert){

		my $sql = "select crl.* from crt_sh_crl_revoked_full as crl where crt_sh_ca_id = $crtsh_cert->{crt_sh_issuer_ca_id} and lower('" . $self->{serial} . "') = substr(crl.serial_number::text, 3);";
		my $crl_entries = CertReader::DB::CrtShRevocationData::CRLrevoked::Manager->get_objects_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
			);
		while (my $crl_entry = $crl_entries->next) {
			$revocation_dates //= [];
			my $date = defined $crl_entry->revocation_date ? $crl_entry->revocation_date : "date_unknown";
			push(@$revocation_dates, $date);
		}

		$revocation_dates //= 0;
	}

	return $revocation_dates;
}

sub is_revoked_cert {
	my $self = shift;

	my $ret = 0;
	if ($self->get_revoked_cert) {
		$ret = 1;
	}

	return $ret;
}

sub get_revoked_cert {
	my $self = shift;

	if (!defined($self->{'revoked_cert'})) {
		$self->{'revoked_cert'} = CertReader::DB::RevokedCerts->cert_to_revokedcert($self);
	}
	return $self->{'revoked_cert'};
}

sub get_issuer_ids {
	my ($self, $postfix) = @_;

	if (defined($self->{'issuer_ids'})) {
		return $self->{'issuer_ids'};
	}

	my $issuer_ids_hash = {};

	if ($self->selfsigned) {
		if ($self->is_valid != 0) {
			$issuer_ids_hash->{$self->id} = 1;
		}
	}

	my $certid = $self->id;
	# my $vts = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
	# 	db => $self->db,
	# 	inject_results => 1,
	# 	sql => "select * from verify_tree_$postfix where certificate = $certid order by store;",
	# );
	# while (my $vt = $vts->next) {
	# 	my $path = $vt->path;
	# 	my $index_issuer = -2;
	# 	my $issuer_cert_id = int((split /\./, $path)[$index_issuer]);
	# 	$issuer_ids_hash->{$issuer_cert_id} = 1;
	# }
	$self->populate_certificate_validities_by_rootcert($postfix);
	my $validities_iter = CertReader::DB::Certificate::CertificateValidityByRootcert::Manager->get_certificate_validities_by_rootcert_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "select * from certificate_validity_by_rootcert_$postfix where certificate = $certid order by store;",
	);
	while ( my $validity = $validities_iter->next ) {
		my $issuer_certids_str = $validity->issuer_certids;
		my @issuer_certids = split(/,/, $issuer_certids_str);
		for my $issuer_certid (@issuer_certids) {
			$issuer_ids_hash->{int($issuer_certid)} = 1;
		}
	}

	my @issuer_ids = keys %$issuer_ids_hash;
	$self->{'issuer_ids'} = \@issuer_ids;
	return $self->{'issuer_ids'};
}

sub get_issuer_certs_iterator {
	my ($self, $postfix) = @_;

	my $issuer_cert_ids = $self->get_issuer_ids($postfix);

	# Array is possibly memory exhaustive
	# my $issuer_certs = [];
	# if (scalar @$issuer_cert_ids) {
		my $issuer_certs_iterator = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => "select * from certificate_$postfix where id in (" . join(",", @$issuer_cert_ids) . ")",
		);
	# }

	return $issuer_certs_iterator;
}

sub get_owner_id {
	my ($self, $postfix) = @_;

	if (defined($self->{'owner_id'})) {
		return $self->{'owner_id'};
	}

	# Relies on uniqueness of cert_relation entries
	my $cert_relation = CertReader::DB::CertificateRelation->new(db => $self->db, 'certificate_id' => $self->id);
	my $cert_relation_exists = $cert_relation->load(use_key => 'certificate_id', speculative => 1);
	if (!$cert_relation_exists) {
		undef;
	}

	my $owner_id = $cert_relation->owner_id;

	$self->{'owner_id'} = $owner_id;
	return $owner_id;
}

sub get_effective_owner_id_at_date {
	my ($self, $date, $postfix) = @_;

	my $owner_id = $self->get_owner_id;
	if (not defined $owner_id) {
		return undef;
	}

	while (1) {
		my $ca_relations = CertReader::DB::CArelation::Manager->get_carelations_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => "select * from ca_relation_$postfix where ca_id = $owner_id and type = 'owned_by' and not_before <= '" . $date . "' order by not_before desc limit 1;",
		);
		if (scalar @$ca_relations == 0) {
			last;
		}

		my $new_owner_id = @$ca_relations[0]->related_ca_id;
		if ($owner_id == $new_owner_id) {
			last;
		}
		$owner_id = $new_owner_id;
	}

	return $owner_id;
}

sub is_issued_by_owner {
	my ($self, $postfix) = @_;

	if (not $self->ca and not $self->is_root_cert) {
		# TODO we do not have owner ids for non-ca certs.
		return 0;
	}

	if (defined($self->{'is_issued_by_owner'})) {
		return $self->{'is_issued_by_owner'};
	}

	my $ret = 0;
	my $owner_id = $self->get_effective_owner_id_at_date($self->not_before, $postfix);

	if (defined($owner_id)) {
		ISSUERID: for my $issuer_id (@{$self->get_issuer_ids($postfix)}) {
			my $issuer_cert = CertReader::DB::Certificate->new( id => $issuer_id );
			$issuer_cert->load();
			my $issuer_owner = $issuer_cert->get_effective_owner_id_at_date($self->not_before, $postfix);
			if (defined $issuer_owner) {
				if ($issuer_owner == $owner_id) {  # still can result in comparison with undef
					$ret = 1;
					last ISSUERID;
				}
			} else {
				warn "ERROR (non-fatal, but with consequences): Unknown owner for issuing cert $issuer_id at $self->{not_before}";
			}
		}
	} else {
		if ($self->ca) {
			warn "ERROR (non-fatal, but with consequences): Unknown owner for CA cert $self->{id}";
		}
	}

	$self->{'is_issued_by_owner'} = $ret;
	return $self->{'is_issued_by_owner'};
}

sub get_owner_chains {
	my ($self, $postfix) = @_;

	if (defined($self->{'owner_chains'})) {
		return $self->{'owner_chains'};
	}

	my $owner_chains = [];

	my $direct_owner_id = $self->get_owner_id($postfix);

	if (!defined($direct_owner_id)) {
		if ($self->is_valid($postfix) == 0) {
			;
		} else {
			if ($self->ca) {
				push @$owner_chains, ["Error_valid_cacert_without_owner (" . $self->id . ")"];
			} else {
				push @$owner_chains, [$self->subject];
			}
		}
		return $owner_chains;
	}

	for my $validitydate (($self->not_before, $self->not_after)) {
		my $new_owner_chain = [];
		my $current_owner_id = $direct_owner_id;
		# fill owner chain
		while (1) {
			my $current_owner = CertReader::DB::CAactor->new(db => $self->db, 'id' => $current_owner_id);
			$current_owner->load();
			push @$new_owner_chain, $current_owner->name;

			my $ca_relations = CertReader::DB::CArelation::Manager->get_carelations_from_sql(
				db => $self->db,
				inject_results => 1,
				sql => "select * from ca_relation_$postfix where ca_id = $current_owner_id and type = 'owned_by' and not_before <= '" . $validitydate . "' order by not_before desc limit 1;",
			);
			if (scalar @$ca_relations == 0) {
				last;
			}

			my $next_owner_id = @$ca_relations[0]->related_ca_id;
			if ($next_owner_id == $current_owner_id) {
				last;
			}
			$current_owner_id = $next_owner_id;
		}

		my $chain_already_known = 0;
		for my $known_owner_chain (@$owner_chains) {
			# note that array_diff() from Array::Utils does not respect order
			if ((join '->', @$new_owner_chain) eq (join '->', @$known_owner_chain)) {
				$chain_already_known = 1;
				last;
			}
		}
		push @$owner_chains, $new_owner_chain if ! $chain_already_known;
	}

	$self->{'owner_chains'} = $owner_chains;
	return $owner_chains;
}

sub get_stores {
	my ($self, $postfix) = @_;

	if (defined($self->{'stores'})) {
		return $self->{'stores'};
	}

	my $stores = [];

	for my $storeid (@{$self->get_storeids}) {
		my $store;
		if (defined $self->{'rootcert_cache'}) {
			if (defined $self->{'rootcert_cache'}->{$storeid}) {
				$store = $self->{'rootcert_cache'}->{$storeid};
			}
		}

		if (not defined($store)) {
			$store = CertReader::DB::RootCerts->new( id => $storeid);
			$store->load();
		}
		push(@$stores, $store);
	}

	# if ($self->is_root_cert) {
	# 	push(@$stores, $self->get_root_cert());
	# }
	#
	# my $certid = $self->id;
	# my $vtiter = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
	# 	db => $self->db,
	# 	inject_results => 1,
	# 	sql => "select * from verify_tree_$postfix where certificate = $certid order by store;",
	# );
	# while ( my $vt = $vtiter->next ) {
	# 	my $store = $vt->rootstore;
	# 	if (!(grep {$_ eq $store } @$stores)) {
	# 		push(@$stores, $store);
	# 	}
	# }

	# requires too much memory
	#$self->{'stores'} = $stores;
	#return $self->{'stores'};
	return $stores;
}

sub get_storeids {
	my ($self, $postfix, $rootstore_cache) = @_;

	if (defined($self->{'storeids'})) {
		return $self->{'storeids'};
	}

	if (not defined($self->{'rootcert_cache'})) {
		$self->{'rootcert_cache'} = $rootstore_cache;
	}

	# my $stores = $self->get_stores($postfix);
	my $storeids = {};

	if ($self->is_root_cert) {
		$storeids->{$self->get_root_cert->id} = 1;
	}

	my $certid = $self->id;
	# my $vtiter = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
	# 	db => $self->db,
	# 	inject_results => 1,
	# 	sql => "select * from verify_tree_$postfix where certificate = $certid order by store;",
	# 	# sql => "select id, certificate, store, ca_chain_id, not_before, not_after, pathlen_allows_issuance from (DISTINCT on (store) store, select id, certificate, ca_chain_id, not_before, not_after, pathlen_allows_issuance from verify_tree_$postfix where certificate = $certid order by store) as tmp;",
	# );
	# while ( my $vt = $vtiter->next ) {
	# 	$storeids->{$vt->store} = 1;
	# }
	$self->populate_certificate_validities_by_rootcert($postfix);
	my $validities_iter = CertReader::DB::Certificate::CertificateValidityByRootcert::Manager->get_certificate_validities_by_rootcert_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "select * from certificate_validity_by_rootcert_$postfix where certificate = $certid order by store;",
	);
	while ( my $validity = $validities_iter->next ) {
		$storeids->{$validity->store} = 1;
	}

	my @storeids = keys %$storeids;
	$self->{'storeids'} = \@storeids;
	return $self->{'storeids'};
}

sub get_storenames {
	my ($self, $postfix) = @_;

	my $stores = $self->get_stores($postfix);

	my $storenames = [];
	for my $rootstore (@$stores) {
		for my $store (@{$rootstore->stores}) {
			if (!(grep {$_ eq $store } @$storenames)) {
				push(@$storenames, $store);
			}
		}
	}

	my @sorted_storenames = sort @$storenames;

	return \@sorted_storenames;
}

sub populate_certificate_validities_by_rootcert {
	my ($self, $postfix, $worker_prefix) = @_;
	$worker_prefix //= "Worker ??";

	my $certid = $self->id;
	my $state = CertReader::DB::Certificate::CertificateValidityByRootcert::State->new(certificate => $self->id);
	if ($state->load(speculative => 1)) {
		if (defined $state->generated_at) {
			# TODO check for new verify_trees and update the state accordingly
			return;  # already populated
		} else {
			# generation was aborted, delete created entries and start from scratch
			say "$worker_prefix  WARNING: Deleting certificate_validities_by_rootcert entries for $certid and redoing generation";
			my $iterator = CertReader::DB::Certificate::CertificateValidityByRootcert::Manager->get_certificate_validities_by_rootcert_iterator_from_sql(
				db => $self->db,
				sql => "select * from certificate_validity_by_rootcert_$postfix where certificate = $certid;",
			);
			while (my $entry = $iterator->next) {
				$entry->delete;
			}
		}
	} else {
		$state->save;  # use existence (with generated_at = Null) as hint that we started generation
	}

	my $watchdog_timeout_seconds = 60;
	my $watchdog_timeout = time + $watchdog_timeout_seconds;
	my $watchdog_function_start = time;

	my $time_vt_query = time;
	my $vtiter = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
		db => $self->db,
		sql => "select * from verify_tree_$postfix where certificate = $certid order by store;",
	);
	my $current_store;
	my $current_validity_periods;
	my $current_issuer_certids = {};
	my $vts_cnt = 0;
	while ( 1 ) {
		my $vt = $vtiter->next;  # loop variable, note: iterator returns false if no more vt is available

		my $finalize_store = 0;
		if (defined $current_store) {
			if ($vt) {
				if ($current_store != $vt->store) {
					# No more vts for the previous store --> finalize
					$finalize_store = 1;
				}
			} else {
				# No more vts at all --> finalize last one
				$finalize_store = 1;
			}
		}

		if ($finalize_store) {
			my $rid = $current_store;
			my $issuer_certids_str = join(',', sort {$a <=> $b} keys %$current_issuer_certids);
			my $periods = $current_validity_periods->get_periods;
			if (scalar @$periods) {
				for my $period (@$periods) {
					my $entry = CertReader::DB::Certificate::CertificateValidityByRootcert->new(
						certificate => $self->id,
						store => $rid,
						not_before => $period->get_notbefore,
						not_after => $period->get_notafter,
						issuer_certids => $issuer_certids_str,
					);
					$entry->save;
				}
			} else {
				# TODO code for legacy verify_trees with not_before and not_after set to Null
				my $entry = CertReader::DB::Certificate::CertificateValidityByRootcert->new(
					certificate => $self->id,
					store => $rid,
					issuer_certids => $issuer_certids_str,
				);
				$entry->save;
			}

			undef $current_validity_periods;
			undef $current_issuer_certids;
		}
		# finalization done, we can continue with the next store


		if (not $vt) {
			last; # no more vt, exit loop
		}

		my $next_store = 0;
		if (defined $current_store) {
			if ($current_store != $vt->store) {
				$next_store = 1;
			}
		} else {
			# very first iteration in loop
			$next_store = 1;
		}

		if ($next_store) {
			$current_store = $vt->store;  # continue with next store
			$current_validity_periods = CertReader::CA::ValidityPeriods->new();
			$current_issuer_certids = {};
		}

		$vts_cnt += 1;
		my $cur_time = time;
		if ($cur_time > $watchdog_timeout) {
			my $running_for_seconds = $cur_time - $watchdog_function_start;
			say "$worker_prefix    WATCHDOG " . __FILE__ . ":". __LINE__ . "  cert $certid, vts_cnt $vts_cnt, running for $running_for_seconds seconds";
			$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
		}

		if (defined $vt->not_before) {
			# add period of verify tree to $current_validity_periods
			my $vt_not_after;
			if (defined $vt->not_after) {
				$vt_not_after = $vt->not_after;
			} else {
				# future is unforeseeable, expect the cert to remain in the store
				$vt_not_after = '2038-01-01';  # cf. year 2038 problem  # TODO more elegant way?
			}
			$current_validity_periods->add_period($vt->not_before, $vt_not_after);
		}
		# and store the id of the issuer certificate
		my $issuer_certid = $vt->get_issuer_certid;
		$current_issuer_certids->{$issuer_certid} = 1;
	}

	$state->generated_at(time2str("%Y-%m-%d %H:%M:%S", $time_vt_query, "UTC"));
	$state->save;
}

sub get_info_by_rootstore {
	my ($self, $postfix, $rootstore_cache, $worker_prefix) = @_;
	$worker_prefix //= "";

	$self->populate_certificate_validities_by_rootcert($postfix, $worker_prefix);

	if (defined $self->{'info_by_rootstore'}) {
		return $self->{'info_by_rootstore'};
	}

	if (not defined($self->{'rootcert_cache'})) {
		$self->{'rootcert_cache'} = $rootstore_cache;
	} else {
		$rootstore_cache = $self->{'rootcert_cache'};
	}

	my $info_by_rootstore = {};

	if ($self->is_root_cert) {
		my $rootcert = $self->get_root_cert;

		# TODO basically a copy of the code below
		my $rootcert_info_by_rootstore = $rootcert->get_info_by_rootstore;
		for my $rootstore_name (keys %$rootcert_info_by_rootstore) {
			$info_by_rootstore->{$rootstore_name} //= {};
			$info_by_rootstore->{$rootstore_name}->{'valid'} //= 0;
			$info_by_rootstore->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();

			my $rootcert_valid = $rootcert_info_by_rootstore->{$rootstore_name}->{'valid'};
			my $rootcert_validity_periods = $rootcert_info_by_rootstore->{$rootstore_name}->{'validity_periods'};

			my $current_validity_periods = CertReader::CA::ValidityPeriods->new();
			for my $period (@{$rootcert_validity_periods->get_periods}) {
				$current_validity_periods->add_period($self->not_before, $self->not_after);
			}

			# WARNING only $current_validity_periods must be changed
			$current_validity_periods->restrict_to_periods($rootcert_validity_periods);
			# TODO the following would be more efficient, but only works for the rootstore case.
			# for my $period (@{$rootcert_validity_periods->get_periods}) {
			# 	$current_validity_periods->add_period($period->get_notbefore, $period->get_notafter);
			# }

			$info_by_rootstore->{$rootstore_name}->{'validity_periods'}->add_periods($current_validity_periods);

			if (not $info_by_rootstore->{$rootstore_name}->{'valid'}) {
				my $found_periods_cnt = scalar @{$current_validity_periods->get_periods};
				if ($found_periods_cnt > 0) {
					$info_by_rootstore->{$rootstore_name}->{'valid'} = 1;
				} else {
					if ($rootcert_valid){
						my $rootcert_periods_cnt = scalar @{$rootcert_validity_periods->get_periods};
						if ($rootcert_periods_cnt == 0) {
							# special case (no validity periods available for rootstore)
							$info_by_rootstore->{$rootstore_name}->{'valid'} = 1;
						}
					}
				}
			}

		}
	}

	my $certid = $self->id;
	my $validities_iter = CertReader::DB::Certificate::CertificateValidityByRootcert::Manager->get_certificate_validities_by_rootcert_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "select * from certificate_validity_by_rootcert_$postfix where certificate = $certid order by store;",
	);
	my $current_store;
	my $current_validity_periods;
	my $vts_cnt = 0;
	while ( 1 ) {
		my $validity = $validities_iter->next;  # loop variable, note: iterator returns false if no more vt is available

		my $finalize_store = 0;
		if (defined $current_store) {
			if ($validity) {
				if ($current_store != $validity->store) {
					# No more validities for the previous store --> finalize
					$finalize_store = 1;
				}
			} else {
				# No more validities at all --> finalize last one
				$finalize_store = 1;
			}
		}

		if ($finalize_store) {

			my $rid = $current_store;
			my $rootcert = $rootstore_cache->{$rid};

			# TODO basically a copy of the code above
			my $rootcert_info_by_rootstore = $rootcert->get_info_by_rootstore;
			for my $rootstore_name (keys %$rootcert_info_by_rootstore) {
				$info_by_rootstore->{$rootstore_name} //= {};
				$info_by_rootstore->{$rootstore_name}->{'valid'} //= 0;
				$info_by_rootstore->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();

				my $rootcert_valid = $rootcert_info_by_rootstore->{$rootstore_name}->{'valid'};
				my $rootcert_validity_periods = $rootcert_info_by_rootstore->{$rootstore_name}->{'validity_periods'};

				my $current_validity_periods_copy = CertReader::CA::ValidityPeriods->new();
				$current_validity_periods_copy->add_periods($current_validity_periods);

				# restrict to period that overlaps with the rootcert validity in $rootstore_name
				# WARNING only $current_validity_periods_copy must be changed
				$current_validity_periods_copy->restrict_to_periods($rootcert_validity_periods);

				$info_by_rootstore->{$rootstore_name}->{'validity_periods'}->add_periods($current_validity_periods_copy);

				my $found_periods_cnt = scalar @{$current_validity_periods_copy->get_periods};
				if ($found_periods_cnt > 0) {
					$info_by_rootstore->{$rootstore_name}->{'valid'} = 1;
				} else {
					if ($rootcert_valid){
						my $rootcert_periods_cnt = scalar @{$rootcert_validity_periods->get_periods};
						if ($rootcert_periods_cnt == 0) {
							# special case (no validity periods available for rootstore)
							$info_by_rootstore->{$rootstore_name}->{'valid'} = 1;
						}
					}
				}
			}

			undef $current_validity_periods;
		}
		# finalization done, we can continue with the next store


		if (not $validity) {
			last; # no more validity entries, exit loop
		}

		my $next_store = 0;
		if (defined $current_store) {
			if ($current_store != $validity->store) {
				$next_store = 1;
			}
		} else {
			# very first iteration in loop
			$next_store = 1;
		}

		if ($next_store) {
			$current_store = $validity->store;  # continue with next store
			$current_validity_periods = CertReader::CA::ValidityPeriods->new();
		}

		if (defined $validity->not_before) {
			# add period of verify tree to $current_validity_periods
			my $validity_not_after;
			if (defined $validity->not_after) {
				$validity_not_after = $validity->not_after;
			} else {
				# future is unforeseeable, expect the cert to remain in the store
				$validity_not_after = '2038-01-01';  # cf. year 2038 problem  # TODO more elegant way?
			}
			$current_validity_periods->add_period($validity->not_before, $validity_not_after);
		}

	}

	$self->{'info_by_rootstore'} = $info_by_rootstore;
	return $self->{'info_by_rootstore'};
}

sub openssl {
	# return the respective openssl certificate for this
	my $self = shift;

	if ( defined($self->{'openssl'}) ) {
		return $self->{'openssl'};
	}

	my $openssl = Crypt::OpenSSL::X509->new_from_string($self->der, Crypt::OpenSSL::X509::FORMAT_ASN1);
#	eval {
#		$openssl = Crypt::OpenSSL::X509->new_from_string($self->der, Crypt::OpenSSL::X509::FORMAT_ASN1);
#	};
#	confess ($self->id." with $@") if $@;
	$self->{'openssl'} = $openssl;

	return $openssl;
}

sub get_pathlen {
	# return the pathlen encoded in the basicConstraints extension or undef
	my $self = shift;

	if ( defined($self->{'pathlen'}) ) {
		return $self->{'pathlen'};
	}

	my $pathlen = undef;
	my $c = $self->openssl;
	if ( $c->num_extensions > 0 ) {
		my $extensions = $c->extensions_by_name;
		while ( my ($name, $ext) = each %$extensions ) {
			if ($name eq "basicConstraints") {
				# my $critical = $ext->critical ? 1 : 0;
				# say "\t" . localtime() . "    $prefix     " . $name . "; (" . $ext->object->oid . ") " . $ext->to_string;
				for my $value (split(/,/, $ext->to_string)) {
					if ($value =~ m/pathlen/) {
						my @name_value = split(/:/, $value);
						$pathlen = int($name_value[1]);
						# say "\t" . localtime() . "                     $value  --  extracted: $pathlen";
						last;
					}
				}
			}
		}
	}
	$self->{'pathlen'} = $pathlen;

	return $pathlen;
}

# sub get_validity_for_attime {
# 	my ($self, $attime_dt) = @_;
# 	croak("get_validity_for_attime: attime_dt undefined") if !defined($attime_dt);
#
# 	for my $validity (@{$self->validities}) {
# 		if ($validity->verify_attime == $attime_dt) {
# 			return $validity;
# 		}
# 	}
# 	return undef;
# }
#
# sub init_validity_if_not_exists {
# 	my ($self, $attime_dt) = @_;
#
# 	my $validity = $self->get_validity_for_attime($attime_dt);
# 	if (defined($validity)) {
# 		return;
# 	}
#
# 	my $validities = $self->validities;
# 	$validity = CertReader::DB::CertificateValidity->new(
# 		certificate => $self->id,
# 		verify_attime => $attime_dt
# 	);
#
# 	# We must check if the certificate is a root of a store and set valid bits accordingly
# 	my $roots = CertReader::DB::RootCerts::Manager->get_rootcerts(
# 		db => $self->db,
# 		query => [ certificate => $self->id ],
# 	);
# 	for my $root ( @$roots ) {
# 		$validity->valid->Bit_On($root->id);
# 	}
#
# 	push(@{$self->validities}, $validity);
# 	# sadly, the push does not yet cause the created validity to be stored in
# 	# the db upon invocation of save:
# 	$self->validities($self->validities);
# 	$self->save;
# }
#
# sub valid {
# 	my ($self, $attime_dt) = @_;
# 	my $validity = $self->get_validity_for_attime($attime_dt);
# 	return $validity->valid;
# }

#__PACKAGE__->meta->make_manager_class('certificates');

package CertReader::DB::Certificate::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::Certificate' }

__PACKAGE__->make_manager_methods('certificates');

sub get_certificates_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::Certificate');
}

sub get_certificates_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::Certificate');
}

sub get_certificates_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::Certificate');
}

sub get_certificate_id_max {
	my ($self, $db, $postfix) = @_;
	my $certiter = $self->get_certificates_iterator_from_sql(
		db => $db,
		inject_results => 1,
		sql => "select * from certificate_$postfix where id = (select max(id) from certificate_$postfix);",
	);
	return $certiter->next->id;
}




package CertReader::DB::Certificate::CertificateValidityByRootcert;

use 5.10.1;
use strict;
use warnings;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'certificate_validity_by_rootcert',
	columns => [
		id => {type => 'serial', not_null => 1, },
		certificate => { type => 'integer', not_null => 1, },
		store => { type => 'integer', not_null => 1, },
		not_before => { type => 'varchar', length => 255 },  # TODO should get attribute not_null at some point
		not_after => { type => 'varchar', length => 255 },  # TODO should get attribute not_null at some point
		issuer_certids => { type => 'string', },  # TODO should get attribute not_null at some point
		],
	pk_columns => 'id',
);

package CertReader::DB::Certificate::CertificateValidityByRootcert::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::Certificate::CertificateValidityByRootcert' }

__PACKAGE__->make_manager_methods('certificate_validities_by_rootcert');

sub get_certificate_validities_by_rootcert_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::Certificate::CertificateValidityByRootcert');
}

sub get_certificate_validities_by_rootcert_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::Certificate::CertificateValidityByRootcert');
}

sub get_certificate_validities_by_rootcert_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::Certificate::CertificateValidityByRootcert');
}


package CertReader::DB::Certificate::CertificateValidityByRootcert::State;

use 5.10.1;
use strict;
use warnings;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'certificate_validity_by_rootcert_state',
	columns => [
		certificate => { type => 'integer', not_null => 1, },
		generated_at => { type => 'varchar', not_null => 1, length => 255 },
		],
	pk_columns => 'certificate',
);

package CertReader::DB::Certificate::CertificateValidityByRootcert::State::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::Certificate::CertificateValidityByRootcert' }

__PACKAGE__->make_manager_methods('certificate_validities_by_rootcert_state');

sub get_certificate_validities_by_rootcert_state_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::Certificate::CertificateValidityByRootcert::State');
}

sub get_certificate_validities_by_rootcert_state_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::Certificate::CertificateValidityByRootcert::State');
}

sub get_certificate_validities_by_rootcert_state_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::Certificate::CertificateValidityByRootcert::State');
}


1;
