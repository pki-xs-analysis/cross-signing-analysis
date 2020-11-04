package CertReader::DB::Chain;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	table => 'chains',
	columns => [
		id => { type => 'serial', },
		chain_hash => { type => 'char', length => 40, not_null => 1 },
		certificates => { type => 'array', not_null => 1 },
       	],
	pk_columns => 'id',
	unique_keys => [ qw/chain_hash/ ],
);

#__PACKAGE__->meta->make_manager_class('chains');

package CertReader::DB::Chain::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::Chain' }

__PACKAGE__->make_manager_methods('chains');
#
# sub get_certificates_sql {
# 	shift->get_objects_sql(@_, object_class => 'CertReader::Certificate');
# }

sub get_chains_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::Chain');
}

1;
