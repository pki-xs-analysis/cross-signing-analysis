package CertReader::DB;

use 5.10.1;
use strict;
use warnings;

use Rose::DB;
our @ISA = qw(Rose::DB);

# Use a private registry for this class
__PACKAGE__->use_private_registry;

my $default_port = 7779;
if ( $ENV{POSTGRES_DB_PORT} ) {
	$default_port = $ENV{POSTGRES_DB_PORT};
}

__PACKAGE__->register_db(
	domain => CertReader::DB->default_domain,
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'notary',
	port => $default_port,
);

__PACKAGE__->register_db(
	domain => 'heartbleed',
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'heartbleed',
	port => 7779,
);

__PACKAGE__->register_db(
	domain => 'heartbleed_full',
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'heartbleed_full',
	port => 7779,
);

__PACKAGE__->register_db(
	domain => 'google',
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'google',
	port => 7779,
);

__PACKAGE__->register_db(
	domain => 'new',
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'notary_new',
	port => 7779,
);

__PACKAGE__->register_db(
	domain => 'ssl',
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'ssl',
	port => 7779,
);

__PACKAGE__->register_db(
	domain => 'greenplum',
	type => CertReader::DB->default_type,
	driver => 'Pg',
	database => 'ssl'
);

__PACKAGE__->register_db(
	domain => 'sqlite',
	type => CertReader::DB->default_type,
	driver => 'SQLite',
	database => 'ssl.sqlite'
);

1;
