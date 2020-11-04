package CertReader::DB::SeenStats;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
	columns => [
		id => { type => 'serial', not_null => 0 },
		file_name => { type => 'varchar', length => 1000, not_null => 1 },
		fields => { type => 'varchar', not_null => 0 },
		begin_time => { type => 'timestamp', not_null => 0 },
		end_time => { type => 'timestamp', not_null => 0 },
		all_lines => { type => 'integer', not_null => 0 },
		invalid_version => { type => 'integer', not_null => 0 },
		packet_loss => { type => 'integer', not_null => 0 },
		all_ports => { type => 'integer', not_null => 0 },
		https_port => { type => 'integer', not_null => 0 },
		smtp_port => { type => 'integer', not_null => 0 },
		with_certs => { type => 'integer', not_null => 0 },
		with_sni => { type => 'integer', not_null => 0 },
		with_cert_and_sni => { type => 'integer', not_null => 0 },
		established => { type => 'integer', not_null => 0 },
		resumed => { type => 'integer', not_null => 0 },
		stapled_ocsp => { type => 'integer', not_null => 0 },
		https_with_certs => { type => 'integer', not_null => 0 },
		https_with_sni => { type => 'integer', not_null => 0 },
		https_with_cert_and_sni => { type => 'integer', not_null => 0 },
		https_withcertsni_ciphers => { type => 'varchar', not_null => 0 },
		https_resumed => { type => 'integer', not_null => 0 },
		non_grid => { type => 'integer', not_null => 0 },
		all_ciphers => { type => 'varchar', not_null => 0 }, #lying; hstore is still too new.
		https_ciphers => { type => 'varchar', not_null => 0 },
		https_withcert_ciphers => { type => 'varchar', not_null => 0 },
		dh_param_sizes => { type => 'varchar', not_null => 0 },
		curves => { type => 'varchar', not_null => 0 },
		client_curves => { type => 'varchar', not_null => 0 },
		client_alpns => { type => 'varchar', not_null => 0 },
		server_alpns => { type => 'varchar', not_null => 0 },
		client_exts => { type => 'varchar', not_null => 0 },
		server_exts => { type => 'varchar', not_null => 0 },
		client_ciphers => { type => 'varchar', not_null => 0 },
		point_formats => { type => 'varchar', not_null => 0 },
		smtp_with_certs => { type => 'integer', not_null => 0 },
		smtp_with_sni => { type => 'integer', not_null => 0 },
		smtp_with_cert_and_sni => { type => 'integer', not_null => 0 },
		smtp_resumed => { type => 'integer', not_null => 0 },
		smtp_ciphers => { type => 'varchar', not_null => 0 },
		smtp_withcert_ciphers => { type => 'varchar', not_null => 0 },
		smtp_withcertsni_ciphers => { type => 'varchar', not_null => 0 },
		versions => { type => 'varchar', not_null => 0 },
		client_versions => { type => 'varchar', not_null => 0 },
		supported_versions => { type => 'varchar', not_null => 0 },
		psk_key_exchange_modes => { type => 'varchar', not_null => 0 },
		client_ciphers_all => { type => 'varchar', not_null => 0 },
		client_extensions_all => { type => 'varchar', not_null => 0 },
		client_ciphers_and_extensions_all => { type => 'varchar', not_null => 0 },
		tls_signature => { type => 'varchar', not_null => 0 },
		ticket_lifetimes => { type => 'varchar', not_null => 0 },
		server_supported_version => { type => 'varchar', not_null => 0 },
		selected_version => { type => 'varchar', not_null => 0 },
       	],

	unique_keys => [
		['file_name']
	],

	pk_columns => 'id',

#	foreign_keys =>
#	[
#		connection =>
#		{
#			class => 'CertReader::Connection',
#			key_columns => { connection_id => 'id' },
#		},
#	],
);

#__PACKAGE__->meta->make_manager_class('seenstats');

package CertReader::DB::SeenStats::Manager;

use base 'Rose::DB::Object::Manager';

sub object_class { 'CertReader::DB::SeenStats' }

__PACKAGE__->make_manager_methods('seenstats');

sub get_seenstats_sql {
	shift->get_objects_sql(@_, object_class => 'CertReader::DB::SeenStats');
}

sub get_seenstats_iterator_from_sql {
	shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::SeenStats');
}


1;


