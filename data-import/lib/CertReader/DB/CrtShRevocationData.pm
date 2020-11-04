package CertReader::DB::CrtShRevocationData::MozillaOneCRL;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'crt_sh_mozilla_onecrl',
	columns => [
		entry_id => { type => 'bigserial', not_null => 1, },
		crt_sh_cert_id => { type => 'bigint', },
		crt_sh_issuer_ca_id => { type => 'integer', },
		issuer_name => { type => 'bytea', },
		last_modified => { type => 'timestamp', },
		serial_number => { type => 'bytea', },
		created => { type => 'timestamp', },
		bug_url => { type => 'text', },
		summary => { type => 'text', },
		subject_name => { type => 'bytea', },
		not_after => { type => 'timestamp', },
		],
	pk_columns => 'entry_id',
	# FOREIGN KEY(crt_sh_cert_id) REFERENCES crt_sh_certifiate_$postfix(crt_sh_id)
);

#__PACKAGE__->meta->make_manager_class('crt_sh_revocations_mozilla_onecrl');

package CertReader::DB::CrtShRevocationData::MozillaOneCRL::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrtShRevocationData::MozillaOneCRL' }

CertReader::DB::CrtShRevocationData::MozillaOneCRL->meta->table("crt_sh_mozilla_onecrl_full");  # TODO hardcoded (from ORM.pm)

__PACKAGE__->make_manager_methods('crt_sh_revocations_mozilla_onecrl');

sub get_crt_sh_revocations_mozilla_onecrl_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::MozillaOneCRL');
}

sub get_crt_sh_revocations_mozilla_onecrl_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::MozillaOneCRL');
}

sub get_crt_sh_revocations_mozilla_onecrl_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::MozillaOneCRL');
}



package CertReader::DB::CrtShRevocationData::GoogleRevoked;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'crt_sh_google_revoked',
    columns => [
		entry_id => { type => 'bigserial', not_null => 1, },
		crt_sh_cert_id => { type => 'bigint', not_null => 1, },
		entry_type => { type => 'text', not_null => 1, },  # type in crt.sh database: revocation_entry_type
        ],
    pk_columns => 'entry_id',
	# FOREIGN KEY(crt_sh_cert_id) REFERENCES crt_sh_certifiate_$postfix(crt_sh_id)
);

#__PACKAGE__->meta->make_manager_class('crt_sh_revocations_google_revoked');

package CertReader::DB::CrtShRevocationData::GoogleRevoked::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrtShRevocationData::GoogleRevoked' }

CertReader::DB::CrtShRevocationData::GoogleRevoked->meta->table("crt_sh_google_revoked_full");  # TODO hardcoded (from ORM.pm)

__PACKAGE__->make_manager_methods('crt_sh_revocations_google_revoked');

sub get_crt_sh_revocations_google_revoked_sql {
    shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::GoogleRevoked');
}

sub get_crt_sh_revocations_google_revoked_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::GoogleRevoked');
}

sub get_crt_sh_revocations_google_revoked_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::GoogleRevoked');
}



package CertReader::DB::CrtShRevocationData::MicrosoftDisallowed;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'crt_sh_microsoft_disallowedcert',
    columns => [
		crt_sh_cert_id => { type => 'bigint', not_null => 1, },
		disallowed_hash => { type => 'bytea', },
		# FOREIGN KEY(crt_sh_cert_id) REFERENCES crt_sh_certifiate_$postfix(crt_sh_id)
        ],
    pk_columns => 'crt_sh_cert_id',
);

#__PACKAGE__->meta->make_manager_class('crt_sh_revocations_microsoft_disallowed');

package CertReader::DB::CrtShRevocationData::MicrosoftDisallowed::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrtShRevocationData::MicrosoftDisallowed' }

CertReader::DB::CrtShRevocationData::MicrosoftDisallowed->meta->table("crt_sh_microsoft_disallowedcert_full");  # TODO hardcoded (from ORM.pm)

__PACKAGE__->make_manager_methods('crt_sh_revocations_microsoft_disallowed');

sub get_crt_sh_revocations_microsoft_disallowed_sql {
    shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::MicrosoftDisallowed');
}

sub get_crt_sh_revocations_microsoft_disallowed_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::MicrosoftDisallowed');
}

sub get_crt_sh_revocations_microsoft_disallowed_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::MicrosoftDisallowed');
}



package CertReader::DB::CrtShRevocationData::CRLrevoked;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;

use Carp;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'crt_sh_crl_revoked',
    columns => [
		entry_id => { type => 'bigserial', not_null => 1, },
		crt_sh_ca_id => { type => 'integer', not_null => 1, },
		serial_number => { type => 'bytea', not_null => 1, },
		reason_code => { type => 'smallint', },
		revocation_date => { type => 'timestamp', },
		last_seen_check_date => { type => 'timestamp' },
        ],
    pk_columns => 'entry_id',
);

#__PACKAGE__->meta->make_manager_class('crt_sh_revocations_crl_revoked');

package CertReader::DB::CrtShRevocationData::CRLrevoked::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrtShRevocationData::CRLrevoked' }

CertReader::DB::CrtShRevocationData::CRLrevoked->meta->table("crt_sh_crl_revoked_full");  # TODO hardcoded (from ORM.pm)

__PACKAGE__->make_manager_methods('crt_sh_revocations_crl_revoked');

sub get_crt_sh_revocations_crl_revoked_sql {
    shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::CRLrevoked');
}

sub get_crt_sh_revocations_crl_revoked_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::CRLrevoked');
}

sub get_crt_sh_revocations_crl_revoked_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrtShRevocationData::CRLrevoked');
}


1;
