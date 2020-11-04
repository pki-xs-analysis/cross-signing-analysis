package CertReader::App::RemoveStore;

# Remove a root-store from the db based on its tag

use 5.16.1;
use strict;
use warnings;
use Carp;
use autodie;

use Data::Dumper;

use CertReader::DB::RootCerts;

use Moose;
with 'MooseX::Runnable';
with 'MooseX::Getopt';
with 'CertReader::Base';
with 'CertReader::ORM';
with 'CertReader::ReadCerts';

no if $] >= 5.017011, warnings => 'experimental::smartmatch';

has 'tag' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	documentation => 'Remove rootstore with this tag',
);

sub run {
	my $self = shift;
	my $postfix = $self->tablepostfix;

	my $certiter = CertReader::DB::RootCerts::Manager->get_rootcerts_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "select * from root_certs_$postfix;",
	);

	while ( my $rootcert = $certiter->next ) {
		if ($self->tag ~~ @{$rootcert->stores}) {
			my $stores = [];
			foreach my $store (@{$rootcert->stores}) {
				if (!($self->tag eq $store)) {
					push(@$stores, $store);
				}
			}
			$rootcert->stores($stores);
			$rootcert->save;

			if ((scalar @{$rootcert->stores}) == 0) {
				my $certid = $rootcert->certificate;
				my $rootcertid = $rootcert->id;
				warn "Deleting rootcert with id $rootcertid  (cert $certid)";
				$rootcert->delete;
			}
		}
	}
}

1;
