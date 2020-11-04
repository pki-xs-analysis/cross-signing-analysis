package CertReader::DB::CArelation;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'ca_relation',
    columns => [
        id => { type => 'serial', },
        ca_id => { type => 'integer', not_null => 1 },
        related_ca_id => { type => 'integer', not_null => 1 },
        type => { type => 'varchar', not_null => 1, length => 255 }, # beware, its implemented as enum in the DB
        not_before => { type => 'varchar', not_null => 1, length => 255 },
  ],
    pk_columns => 'id',

    foreign_keys =>
    [
        ca => {
            class => 'CertReader::DB::CAactor',
            key_columns => { ca_id => 'id' },
            type => 'many to one',
        },
        related_ca => {
            class => 'CertReader::DB::CAactor',
            key_columns => { related_ca_id => 'id' },
            type => 'many to one',
        },
    ],
);


#__PACKAGE__->meta->make_manager_class('carelations');

package CertReader::DB::CArelation::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CArelation' }

__PACKAGE__->make_manager_methods('carelations');

sub get_carelations_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CArelation');
}

sub get_carelations_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CArelation');
}

1;
