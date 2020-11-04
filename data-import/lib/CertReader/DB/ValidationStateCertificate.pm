package CertReader::DB::ValidationStateCertificate;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'validation_state_certificate',
    columns => [
        cert_id => { type => 'integer', },
        verified_at => { type => 'varchar', length => 255},  # __fully__ verified at that time
        partial_state_started_at => { type => 'varchar', length => 255},
        partial_state_chainlen => { type => 'integer', },
        partial_state_rid => { type => 'integer', },
        partial_state_cachain => { type => 'bigint', },
  ],
    pk_columns => 'cert_id',

    relationships => [
        certificate => {
            type => 'one to one',
            class => 'CertReader::DB::Certificate',
            column_map => { cert_id => 'id' },
        },
    ],
);



#__PACKAGE__->meta->make_manager_class('vs_cert');

package CertReader::DB::ValidationStateCertificate::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::ValidationStateCertificate' }

__PACKAGE__->make_manager_methods('vs_cert');

sub get_vs_cert_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::ValidationStateCertificate');
}

sub get_vs_cert_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::ValidationStateCertificate');
}


1;
