package CertReader::App::ImportStatistics;

# This is a helper file that imports the *.statistics files, in case we
# have to re-read them.

use 5.14.1;
use strict;
use warnings;

use Carp;
use YAML::XS 'LoadFile';
use Data::Dumper;
use Pg::hstore;

use Moose;
with 'CertReader::Base';

has 'tablename' => (
	is => 'rw',
	isa => 'Str',
	required => '0',
	documentation => "Specify tablename to write data to, if different from seen_stats_\$postfix"
);

sub run {
	my $self = shift;

	croak("Need file") unless (scalar @ARGV >= 1);

	$self->db;
	if ( defined($self->tablename) ) {
		say STDERR "Resetting table name to ".$self->tablename;
		CertReader::DB::SeenStats->meta->table($self->tablename);
	}


	for my $file ( @ARGV ) {
		say STDERR "Reading $file";
		unless ( -f $file ) {
			say STDERR "$file does not exist!";
			next;
		}
		$self->readStats($file);
	}
}

sub readStats {
	my ($self, $file) = @_;
	my $ref = LoadFile($file);
	if ( ref($ref) ne "HASH" || ! defined($ref->{all_ports}) ) {
		say STDERR "Data file $file does not contain necessary keywords";
		return;
	}

	$file =~ s/\.statistics(_.*)?//;

	my $test = CertReader::DB::SeenStats->new(file_name => $file);
	if ( $test->load(use_key => 'file_name', speculative=> 1) ) {
		say "skipping duplicate $file";
		return 0
	}
	$test = CertReader::DB::SeenStats->new(file_name => $ref->{file_name});
	if ( $test->load(use_key => 'file_name', speculative=> 1) ) {
		say "skipping duplicate $file";
		return 0;
	}

	my @hstorelines = qw/all_ciphers https_ciphers https_withcert_ciphers https_withcertsni_ciphers smtp_ciphers smtp_withcert_ciphers smtp_withcertsni_ciphers versions dh_param_sizes point_formats client_curves curves client_alpns server_alpns client_exts server_exts client_ciphers
client_versions supported_versions psk_key_exchange_modes client_ciphers_all client_extensions_all client_ciphers_and_extensions_all
tls_signature ticket_lifetimes server_supported_version selected_version/;

 	for my $var (@hstorelines)	{
		if ( !defined($ref->{$var}) ) {
			croak("Missing var $var?");
		}
		$ref->{$var} = Pg::hstore::encode($ref->{$var});
	 }

	delete($ref->{signature_sniips});
	my $dbstats = CertReader::DB::SeenStats->new(%$ref);
	$dbstats->save;
}

1;
