package CertReader::DB::CrossSignCandidate;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;
use Crypt::OpenSSL::X509;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'cross_sign_candidate',
	columns => [
		id => { type => 'serial', },
		subject => { type => 'text', not_null => 1, },
		key_mod => { type => 'varchar'  },
       	],
	pk_columns => 'id',
	# unique_keys => [ qw/cert_hash fingerprint_sha1 fingerprint_sha256 fingerprint_sha512/ ],
);


#__PACKAGE__->meta->make_manager_class('crosssigncandidate');

package CertReader::DB::CrossSignCandidate::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrossSignCandidate' }

__PACKAGE__->make_manager_methods('crosssigncandidate');

sub get_crosssigncandidates_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrossSignCandidate');
}

sub get_crosssigncandidates_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrossSignCandidate');
}

sub get_crosssigncandidate_for_cert {
	my ($self, $db, $postfix, $cert) = @_;
	my $subject = $db->dbh->quote($cert->subject);
	my $key_mod = $db->dbh->quote($cert->key_mod);
	my $certiter = $self->get_crosssigncandidates_iterator_from_sql(
		db => $db,
		inject_results => 1,
		# we need to use md5 to make use of the index
		sql => "select * from cross_sign_candidate_$postfix where md5(subject) = md5($subject) and md5(key_mod) = md5($key_mod);",
	);

	# check that we do not have a false positive due to a hash collision
	while (my $cur = $certiter->next) {
		if ($cur->subject eq $cert->subject and $cur->key_mod eq $cert->key_mod) {
			return $cur;
		}
	}

	return 0;
}

sub get_crosssigncandidate_id_max {
	my ($self, $db, $postfix) = @_;
	my $certiter = $self->get_crosssigncandidates_iterator_from_sql(
		db => $db,
		inject_results => 1,
		sql => "select * from cross_sign_candidate_$postfix where id = (select max(id) from cross_sign_candidate_$postfix);",
	);
	return $certiter->next->id;
}


package CertReader::DB::CrossSignCandidateCert;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;
use Crypt::OpenSSL::X509;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'csc_cert',
	columns => [
		id => { type => 'serial', },
		csc_id => { type => 'integer', not_null => 1 },
		cert_id => { type => 'integer', not_null => 1 },
		from_subj_alt_ext => { type => 'boolean' },
		],
	pk_columns => 'id',
	# unique_keys => [ qw/cert_hash fingerprint_sha1 fingerprint_sha256 fingerprint_sha512/ ],

	foreign_keys =>
	[
		crosssigncandidate => {
			class => 'CertReader::DB::CrossSignCandidate',
			key_columns => { csc_id => 'id' },
		},
		cert => {
			class => 'CertReader::DB::Certificate',
			key_columns => { cert_id => 'id' },
		},
	]
);


#__PACKAGE__->meta->make_manager_class('crosssigncandidatecert');

package CertReader::DB::CrossSignCandidateCert::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrossSignCandidateCert' }

__PACKAGE__->make_manager_methods('crosssigncandidatecert');

# sub get_csc_cert_sql {
# 	shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrossSignCandidateCert');
# }

sub get_csc_cert_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrossSignCandidateCert');
}

sub get_csc_certs_iterator_for_csc {
	my ($self, $db, $postfix, $csc) = @_;

	my $csc_id = $csc->id;
	my $certiter = $self->get_csc_cert_iterator_from_sql(
		db => $db,
		inject_results => 1,
		sql => "select * from csc_cert_$postfix where csc_id = $csc_id;",
	);
	return $certiter;
}

sub get_csc_certs_iterator_for_csc_ordered_by_notbefore_and_notafter {
	my ($self, $db, $postfix, $csc) = @_;

	my $csc_id = $csc->id;
	my $certiter = $self->get_csc_cert_iterator_from_sql(
		db => $db,
		inject_results => 1,
		sql => "select csc_cert.* from (select * from csc_cert_$postfix where csc_id = $csc_id) as csc_cert left join certificate_full as cert on csc_cert.cert_id = cert.id order by cert.not_before ASC, cert.not_after ASC;",
	);
	return $certiter;
}

sub get_csc_cert_for_csc_and_cert {
	my ($self, $db, $postfix, $csc, $cert) = @_;
	my $cert_id = $cert->id;
	my $csc_id = $csc->id;
	my $certiter = $self->get_csc_cert_iterator_from_sql(
		db => $db,
		inject_results => 1,
		sql => "select * from csc_cert_$postfix where csc_id = $csc_id and cert_id = $cert_id;",
	);
	return $certiter->next;
}

sub get_csc_cert_iterator_for_cert {
	my ($self, $db, $postfix, $cert) = @_;
	my $cert_id = $cert->id;
	my $csc_cert_iter = $self->get_csc_cert_iterator_from_sql(
		db => $db,
		inject_results => 1,
		sql => "select * from csc_cert_$postfix where cert_id = $cert_id;",
	);
	return $csc_cert_iter;
}



package CertReader::DB::CrossSignCandidateMetaData;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

use Date::Format;


__PACKAGE__->meta->setup
(
    table => 'csc_metadata',
    columns => [
        csc_id => { type => 'integer', },
        evaluated_at => { type => 'varchar', length => 255},

        any_cert_valid => { type => 'bool' },
        cs_valid => { type => 'bool' },
        with_root => { type => 'bool' },
        with_revoked_root => { type => 'bool' },

        cs_rootcert => { type => 'bool' },
        cs_intermediate => { type => 'bool' },
        cs_leaf => { type => 'bool' },
        cs_leafmix => { type => 'bool' },
        cs_multisignalgs => { type => 'bool' },
        # cs_extstorecover => { type => 'bool' },
        cs_expanding_store => { type => 'bool' },
        cs_expanding_time => { type => 'bool' },
        cs_alternpaths => { type => 'bool' },
        cs_bootstrapping => { type => 'bool' },

        cs_ca_intern_singlecert => { type => 'bool' },
        cs_ca_intern_multicert => { type => 'bool' },
        cs_ca_intern_multicert_oneca => { type => 'bool' },
        cs_ca_intern_multicas => { type => 'bool' },

        cs_ca_extern_singlecert => { type => 'bool' },
        cs_ca_extern_multicert => { type => 'bool' },
        cs_ca_extern_multicert_oneca => { type => 'bool' },
        cs_ca_extern_multicas => { type => 'bool' },

        cs_leaf_singleca => { type => 'bool' },
        cs_leaf_multicas => { type => 'bool' },
        cs_leaf_singlecert_oneca => { type => 'bool' },
        cs_leaf_multicert_oneca => { type => 'bool' },

        validity_gap => { type => 'bool' },
        sub_groups => { type => 'integer' },
        largest_validcertcnt_subgroups => { type => 'integer' },

  ],
    pk_columns => 'csc_id',

    relationships => [
        cross_sign_candidate => {
            type => 'one to one',
            class => 'CertReader::DB::CrossSignCandidate',
            column_map => { csc_id => 'id' },
        },
    ],
);


#__PACKAGE__->meta->make_manager_class('csc_metadata_objs');

package CertReader::DB::CrossSignCandidateMetaData::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrossSignCandidateMetaData' }

__PACKAGE__->make_manager_methods('csc_metadata_objs');

sub get_csc_metadata_objs_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CrossSignCandidateMetaData');
}

sub get_csc_metadata_objs_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrossSignCandidateMetaData');
}



package CertReader::DB::EvalstateCrossSignCandidate;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'csc_evalstate',
    columns => [
        csc_id => { type => 'integer', },
        evaluated_at => { type => 'varchar', length => 255},
  ],
    pk_columns => 'csc_id',

);


#__PACKAGE__->meta->make_manager_class('evalstate_csc');

package CertReader::DB::EvalstateCrossSignCandidate::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::EvalstateCrossSignCandidate' }

__PACKAGE__->make_manager_methods('evalstate_csc');

sub get_evalstate_csc_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::EvalstateCrossSignCandidate');
}

sub get_evalstate_csc_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::EvalstateCrossSignCandidate');
}


1;
