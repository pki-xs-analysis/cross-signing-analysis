package CertReader::DB::Object;

use 5.10.1;
use strict;
use warnings;

use CertReader::DB;
use base qw/Rose::DB::Object/;

sub init_db {
	CertReader::DB->new_or_cached;
}

1;
