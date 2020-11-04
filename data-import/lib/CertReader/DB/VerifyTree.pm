package CertReader::DB::VerifyTree;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'verify_tree',
	columns => [
		id => { type => 'bigserial', },
		certificate => { type => 'integer', not_null => 1 },
		store => { type => 'integer', not_null => 1 },
		ca_chain_id => { type => 'bigint', not_null => 1 },
		not_before => { type => 'varchar', length => 255},  # TODO we should add 'not_null => 1,' at some point
		not_after => { type => 'varchar', length => 255},  # TODO we should add 'not_null => 1,' at some point
        pathlen_allows_issuance => { type => 'boolean' },
  ],
    pk_columns => 'id',

    relationships => [
        rootstore => {
            type => 'many to one',
            class => 'CertReader::DB::RootCerts',
            column_map => { store => 'id' },
        },
        ca_chain => {
            type => 'many to one',
            class => 'CertReader::DB::CaChain',
            column_map => { ca_chain_id => 'id' },
        }
    ],
);

sub path {
    my $self = shift;

    if (defined $self->{'_path'}) {
        return $self->{'_path'}
    }

    my @cert_ids;
    push(@cert_ids, $self->rootstore->certificate);
    push(@cert_ids, reverse @{$self->ca_chain->cert_ids});
    push(@cert_ids, $self->certificate);
    my $path = join('.', @cert_ids);

    $self->{'_path'} = $path;
    return $self->{'_path'};
}

sub get_issuer_certid {
    my $self = shift;

    my $path = $self->path;
    my $index_issuer = -2;
    my $issuer_certid = int((split /\./, $path)[$index_issuer]);

    return $issuer_certid;
}


#__PACKAGE__->meta->make_manager_class('verifytrees');

package CertReader::DB::VerifyTree::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::VerifyTree' }

__PACKAGE__->make_manager_methods('verifytrees');

sub get_verifypaths_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::VerifyTree');
}

sub get_verifypaths_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::VerifyTree');
}

1;
