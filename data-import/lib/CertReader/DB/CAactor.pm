package CertReader::DB::CAactor;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'ca_actor',
    columns => [
        id => { type => 'serial', },
        name => { type => 'varchar', not_null => 1, length => 512 },
        ],
    pk_columns => 'id',
    unique_keys => [ qw/name/ ],
);

sub to_insert_statement {
    my $self = shift;

    my $insert_statement = "INSERT INTO " . CertReader::DB::CAactor->meta->table;
    $insert_statement .= " (name) VALUES (";
    $insert_statement .= "'" . $self->name . "'";
    $insert_statement .= ");";

    return $insert_statement;
}

package CertReader::DB::CAactor::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CAactor' }

__PACKAGE__->make_manager_methods('caactors');

sub get_caactors_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CAactor');
}

sub get_caactors_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CAactor');
}

1;
