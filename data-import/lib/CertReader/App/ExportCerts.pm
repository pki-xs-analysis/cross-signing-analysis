package CertReader::App::ExportCerts;

use 5.14.1;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use List::Util qw[min max];

use Moose;

use Crypt::OpenSSL::X509;

with 'CertReader::Base';
with 'CertReader::CA';
with 'CertReader::CertCache';

my $stepsize = 100000;

has 'ca_only' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Only export certificates with ca = True',
);

has 'out' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	documentation => "Certificates will be written to this file.",
);

has 'append' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Append to the output file. In default mode, the file will be truncated.',
);

has 'force' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Force overwriting of existing file.',
);

has 'stepsize' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $stepsize,
	documentation => "Maximum number of lines requested from the database in one query. Default: $stepsize",
);

has 'start_with_certid' => (
	is => 'rw',
	isa => 'Int',
	required => 0,
	default => 0,
	documentation => "Skip all certificates with id smaller than given. Usually only needed to resume work.",
);

sub run {
	my $self = shift;
	my $postfix = $self->tablepostfix;
	my $stepsize = $self->stepsize;

	my $filehandle;
	if (-e $self->out) {
		# file exists
		if ($self->append) {
			say "Appending to existing file " . $self->out;
			open $filehandle, ">>" . $self->out or die "Couldn't open file " . $self->out . ", $!";
		} elsif ($self->force) {
			say "Truncating existing file " . $self->out;
			open $filehandle, "+>" . $self->out or die "Couldn't open file " . $self->out . ", $!";
		} else {
			croak("Refusing to write to existing file " . $self->out);
		}
	} else {
		open $filehandle, ">" . $self->out or die "Couldn't open file " . $self->out . ", $!";
	}

	my $currid = 0;
	my $lastid = -1;

	if ($self->start_with_certid) {
		$currid = $self->start_with_certid;
	}

	my $certid_max = CertReader::DB::Certificate::Manager->get_certificate_id_max($self->db, $postfix);
	say "We have $certid_max certificates in the database";

	while( $lastid < $certid_max ) {
		$lastid = min($currid + ($stepsize - 1), $certid_max);

		my $sql = "select * from certificate_$postfix where id >= $currid and id <= $lastid order by id asc;";
		if ($self->ca_only) {
			$sql = "select * from certificate_$postfix where ca = True and id >= $currid and id <= $lastid order by id asc;";
		}

		my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);

		while ( my $cert = $certiter->next ) {
			say "Writing cert (id: " . $cert->id . ")";
			print $filehandle $cert->openssl->as_string(Crypt::OpenSSL::X509::FORMAT_PEM);
		}

		$currid = $lastid + 1;
		$filehandle->flush;
	}

	close($filehandle);

	exit(0);
}

1;
