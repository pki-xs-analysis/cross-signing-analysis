package CertReader::DB::CertificateRelation;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'certificate_relation',
    columns => [
        id => { type => 'serial', },
        certificate_id => { type => 'integer', not_null => 1 },
        owner_id => { type => 'integer', not_null => 1 },
  ],
    pk_columns => 'id',
    unique_keys => [ qw/certificate_id/ ],

    foreign_keys => 
    [
        owner => {
            class => 'CertReader::DB::CAactor',
            key_columns => { owner_id => 'id' },
            type => 'many to one',
        },
    ],
);


#__PACKAGE__->meta->make_manager_class('certificaterelations');

package CertReader::DB::CertificateRelation::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CertificateRelation' }

__PACKAGE__->make_manager_methods('certificaterelations');

sub get_certificaterelations_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CertificateRelation');
}

sub get_certificaterelations_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CertificateRelation');
}

1;
