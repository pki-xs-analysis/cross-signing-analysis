package CertReader::DB::ValidationStateRootcert;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'validation_state_rootcert',
    columns => [
        rootcert_id => { type => 'integer', },
        verified_at => { type => 'varchar', length => 255},  # __fully__ verified at that time
        partial_state_started_at => { type => 'varchar', length => 255},
        partial_state_chainlen => { type => 'integer', },
  ],
    pk_columns => 'rootcert_id',

    relationships => [
        certificate => {
            type => 'one to one',
            class => 'CertReader::DB::RootCerts',
            column_map => { rootcert_id => 'id' },
        },
        subcert_states => {
            type => 'one to many',
            class => 'CertReader::DB::ValidationStateRootcert::SubstateCert',
            column_map => { rootcert_id => 'id' },
        },
    ],
);


#__PACKAGE__->meta->make_manager_class('vs_rootcert');

package CertReader::DB::ValidationStateRootcert::Manager;

use base 'Rose::DB::Object::Manager';

use Digest::MD5 qw/md5_hex/;
use Encode qw/encode_utf8/;
use Date::Format;


sub object_class { 'CertReader::DB::ValidationStateRootcert' }

__PACKAGE__->make_manager_methods('vs_rootcert');

sub get_vs_rootcert_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::ValidationStateRootcert');
}

sub get_vs_rootcert_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::ValidationStateRootcert');
}





package CertReader::DB::ValidationStateRootcert::SubstateCert;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'validation_state_rootcert_sub_cert',
    columns => [
        id => { type => 'serial', },
        rootcert_id => { type => 'integer', },
        cert_id => { type => 'integer', },
        partial_state_started_at => { type => 'varchar', length => 255},  # verified chain_len at that time
        partial_state_chainlen => { type => 'integer',},
        partial_state_cachain => { type => 'bigint', },
        partial_state_found_valid_chain => { type => 'boolean', },
  ],
    pk_columns => 'id',

    relationships => [
        rootcert => {
            type => 'one to one',
            class => 'CertReader::DB::RootCerts',
            column_map => { rootcert_id => 'id' },
        },
        rootcert_state => {
            type => 'many to one',
            class => 'CertReader::DB::ValidationStateRootcert',
            column_map => { rootcert_id => 'rootcert_id' },
        },
    ],
);


#__PACKAGE__->meta->make_manager_class('vs_cert_in_rootcert');

package CertReader::DB::ValidationStateRootcert::SubstateCert::Manager;

use base 'Rose::DB::Object::Manager';

use Digest::MD5 qw/md5_hex/;
use Encode qw/encode_utf8/;
use Date::Format;


sub object_class { 'CertReader::DB::ValidationStateRootcert::SubstateCert' }

__PACKAGE__->make_manager_methods('vs_cert_in_rootcert');

sub get_vs_cert_in_rootcert_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::ValidationStateRootcert::SubstateCert');
}

sub get_vs_cert_in_rootcert_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::ValidationStateRootcert::SubstateCert');
}

sub get_vs_cert_in_rootcert_for_rid_and_cert {
    my ($self, $rid, $cert) = @_;
    my $postfix = 'full';  # TODO hardcoded, should be obtained from somewhere

    my $cachains_it = $self->get_vs_cert_in_rootcert_iterator_from_sql(
        db => $cert->db,
        sql => "select * from validation_state_rootcert_sub_cert_$postfix where rootcert_id = $rid and cert_id = $cert->{id};",
    );
    return $cachains_it->next;
}

1;
