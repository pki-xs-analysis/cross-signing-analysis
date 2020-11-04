package CertReader::DB::RootstoreVersion;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

# TODO should get an attime entry to reflect rootstore changes over time
__PACKAGE__->meta->setup
(
    table => 'rootstore_version',
    columns => [
        id => { type => 'serial', },
        rootstore_name => { type => 'varchar', not_null => 1, length => 255 },
        tag => { type => 'varchar', not_null => 1, length => 255 },
        start_date => { type => 'varchar', length => 255 }, # Null (i.e. undef in perl) means that we do not know the start date
        end_date => { type => 'varchar', length => 255 },  # Null (i.e. undef in perl) means that no more recent version of the rootstore is known
    ],
    pk_columns => 'id',
    unique_keys => [ qw/tag/ ],
);




# __PACKAGE__->meta->make_manager_class('rootstoreversions');

package CertReader::DB::RootstoreVersion::Manager;

use base 'Rose::DB::Object::Manager';

use Date::Parse;

sub object_class { 'CertReader::DB::RootstoreVersion' }

__PACKAGE__->make_manager_methods('rootstoreversions');

sub get_rootstoreversions_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::RootstoreVersion');
}

sub add_or_update_rootstoreversion {
    my ($self, $rootstore_name, $tag, $start_date, $end_date) = @_;

    # TODO nasty workaround; The corresponding action in ORM.pm seems to not have an effect here; Do this properly
    my $postfix = 'full';
    CertReader::DB::RootstoreVersion->meta->table("rootstore_version_$postfix");

    my $rsv = CertReader::DB::RootstoreVersion->new( tag => $tag );
    if ( $rsv->load(use_key => 'tag', speculative => 1) ) {
        my $changed = 0;
        if ( defined($start_date) != defined($rsv->start_date)
            or (defined($start_date) and (str2time($start_date) != str2time($rsv->start_date)))
            )
        {
            $rsv->start_date($start_date);
            $changed = 1;
        }
        if (defined($end_date) != defined($rsv->end_date)
            or (defined($end_date) and (str2time($end_date) != str2time($rsv->end_date)))
            )
        {
            $rsv->end_date($end_date);
            $changed = 1;
        }

        if ($changed) {
            $rsv->save;
        }
    } else {
        $rsv->rootstore_name($rootstore_name);
        $rsv->start_date($start_date);
        $rsv->end_date($end_date);

        $rsv->save;
    }

    return $rsv->id;
}

1;
