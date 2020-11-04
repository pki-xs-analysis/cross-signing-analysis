package CertReader::DB::CrtShCertificate;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;
use Crypt::OpenSSL::X509;

use Carp;

use Array::Utils qw(:all);

use CertReader::DB::Certificate;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'crt_sh_certificate',
	columns => [
		crt_sh_id => { type => 'bigint', },
		crt_sh_issuer_ca_id => { type => 'integer', not_null => 1, },
		certificate_id_local => { type => 'integer', not_null => 1, },
		],
	pk_columns => 'crt_sh_id',
	unique_keys => [ qw/certificate_id_local/ ],

	foreign_keys =>
	[
		cert => {
			class => 'CertReader::DB::Certificate',
			key_columns => { certificate_id_local => 'id' },
		},
	]

);

#__PACKAGE__->meta->make_manager_class('certificates');

package CertReader::DB::CrtShCertificate::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CrtShCertificate' }

__PACKAGE__->make_manager_methods('crt_sh_certificates');

sub get_certificates_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::CrtShCertificate');
}

sub get_certificates_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CrtShCertificate');
}

sub get_certificates_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CrtShCertificate');
}

1;
