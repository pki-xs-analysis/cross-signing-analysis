package CertReader::DB::RootCerts;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;

use CertReader::DB::RootstoreVersion;
use CertReader::CA::ValidityPeriods;

use Date::Parse;
use List::Util qw[min max];

use base qw/CertReader::DB::Object/;

# TODO should get an attime entry to reflect rootstore changes over time
__PACKAGE__->meta->setup
(
	table => 'root_certs',
	columns => [
		id => { type => 'serial', },
		certificate => { type => 'integer', not_null => 1 },
		stores => { type => 'array', not_null => 1 },
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

# TODO Should be aware of the verification attime
sub cert_to_rootcert {
	my ($cls, $cert) = @_;

	my $rc = $cls->new(certificate => $cert->id);

	my $res = $rc->load(use_key => 'certificate', speculative => 1);
	if ( $res ) {
		return $rc;
	} else {
		return $res;
	}
}

sub get_info_by_rootstore {
	my $self = shift;
	my $validity_periods_by_rootstore_name = {};

	if (defined $self->{'info_by_rootstore'}) {
		return $self->{'info_by_rootstore'};
	}

	$self->{'info_by_rootstore'} = {};

	for my $tag (@{$self->stores}) {
		my $rsv = CertReader::DB::RootstoreVersion->new( tag => $tag );
		$rsv->load;

		my $rootstore_name = $rsv->rootstore_name;

		$self->{'info_by_rootstore'}->{$rootstore_name} //= {};
		$self->{'info_by_rootstore'}->{$rootstore_name}->{'valid'} = 1;
		$self->{'info_by_rootstore'}->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();

		if (defined $rsv->start_date) {
			my $start_date = $rsv->start_date;
			my $end_date;
			if (defined $rsv->end_date) {
				$end_date = $rsv->end_date;
			} else {
				# future is unforeseeable, expect the cert to remain in the store
				$end_date = '2038-01-01';  # cf. year 2038 problem  # TODO more elegant way?
			}

			$self->{'info_by_rootstore'}->{$rootstore_name}->{'validity_periods'}->add_period($start_date, $end_date);
		}
	}

	return $self->{'info_by_rootstore'};
}


# __PACKAGE__->meta->make_manager_class('rootcerts');

package CertReader::DB::RootCerts::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::RootCerts' }

__PACKAGE__->make_manager_methods('rootcerts');

sub get_rootcerts_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::RootCerts');
}

1;
