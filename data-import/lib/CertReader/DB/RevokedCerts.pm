package CertReader::DB::RevokedCerts;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'revoked_certs',
	columns => [
		id => { type => 'serial', },
		certificate => { type => 'integer', not_null => 1 },
		flags => { type => 'array', not_null => 1 },
	],
	pk_columns => 'id',
	unique_keys => [ qw/certificate/ ],

	foreign_keys =>
	[
		cert => {
			class => 'CertReader::DB::Certificate',
			key_columns => { certificate => 'id' },
		},
	]
);

sub cert_to_revokedcert {
	my ($cls, $cert) = @_;

	my $rc = $cls->new(certificate => $cert->id);

	my $res = $rc->load(use_key => 'certificate', speculative => 1);
	if ( $res ) {
		return $rc;
	} else {
		return $res;
	}
}

__PACKAGE__->meta->make_manager_class('revokedcerts');

1;
