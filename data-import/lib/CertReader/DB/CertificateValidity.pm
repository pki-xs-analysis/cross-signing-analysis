package CertReader::DB::CertificateValidity;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use Data::Dumper;
# use Crypt::OpenSSL::X509;

use Carp;

# use Array::Utils qw(:all);

# use CertReader::DB::VerifyTree;
# use CertReader::DB::RootCerts;
# use CertReader::DB::RevokedCerts;
# use CertReader::DB::CertificateRelation;
# use CertReader::DB::CArelation;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'certificate_validity',
	columns => [
		certificate => { type => 'serial', },
		valid => { type => 'boolean', not_null => 1, default => 0},
		],
	pk_columns => 'certificate',
);


#__PACKAGE__->meta->make_manager_class('certificates');

package CertReader::DB::CertificateValidity::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CertificateValidity' }

__PACKAGE__->make_manager_methods('certificate_validities');

sub get_certificate_validities_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::CertificateValidity');
}

sub get_certificate_validities_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CertificateValidity');
}

sub get_certificate_validities_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CertificateValidity');
}

sub get_certificate_validity_for_certid {
	my ($self, $db, $postfix, $certid) = @_;

	my $key = 'certificate';
	my $test = CertReader::DB::CertificateValidity->new(db => $db, $key => $certid);
	if ( $test->load(speculative => 1) ) {
		return $test;
	}
	return 0;

}

1;
