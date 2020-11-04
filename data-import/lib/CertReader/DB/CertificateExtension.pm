package CertReader::DB::CertificateExtension;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
#	table => "conn_to_certs",
	columns => [
		id => { type => 'serial', not_null => 0 },
		certificate_id => { type => 'integer', not_null => 1 },
		critical => { type => 'boolean', not_null => 1 },
		name => { type => 'varchar', length => 255, not_null => 1 },
		oid => { type => 'varchar', length => 255, not_null => 1 },
		value => { type => 'bytea', not_null => 1 },
	],
	pk_columns => 'id',

	foreign_keys =>
	[
		certificate =>
		{
			class => 'CertReader::DB::Certificate',
			key_columns => { certificate_id => 'id' },
		},
	],
);

#__PACKAGE__->meta->make_manager_class('certificateextensions');

package CertReader::DB::CertificateExtension::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::CertificateExtension' }

__PACKAGE__->make_manager_methods('certificateextensions');

sub get_certificateextensions_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::CertificateExtension');
}

sub get_certificateextensions_from_sql {
	shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CertificateExtension');
}

1;

