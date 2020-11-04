package CertReader::App::ImportStoreIntermediates;

# Import a root-store into the db and tag it correctly

use 5.16.1;
use strict;
use warnings;
use Carp;
use autodie;

use Moose;
with 'MooseX::Runnable';
with 'MooseX::Getopt';
with 'CertReader::Base';
with 'CertReader::ORM';
with 'CertReader::ReadCerts';

use Crypt::OpenSSL::X509;

no if $] >= 5.017011, warnings => 'experimental::smartmatch';

has 'tag' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	documentation => 'Tag rootstore with...',
);

has 'cacerts' => (
	is => 'ro',
	isa => 'Bool',
	required => '0',
	default => '0',
	documentation => "Only store CA certificates in the database.",
);

sub run {
	my $self = shift;

	my $cert;
	my $importcount = 0;

	while ( <> ) {
		if (/BEGIN C/../END C/ ) {
			$cert .= $_;
			if ( /END C/ ) {
				# TODO No error on non-pem format
				my $id = $self->readsinglecert($cert, Crypt::OpenSSL::X509::FORMAT_PEM);
				# my $test = CertReader::DB::RootCerts->new(certificate => $id);

				# if ( $test->load(use_key => 'certificate', speculative => 1) ) {
				# 	push(@{$test->stores}, $self->tag) unless ($self->tag ~~ @{$test->stores});
				# 	$test->save;
				# } else {
				# 	$test->stores([$self->tag]);
				# 	$test->save;
				# }
				# each root-certificate is valid for itself.
				$cert = "";
				my $rcert = CertReader::DB::Certificate->new(id => $id);
				croak ("Root rcertificate not found?") unless ( $rcert->load(speculative => 1) );
				# unless ( $rcert->valid->bit_test($test->id) ) {
				# 	$rcert->valid->Bit_On($test->id);
				# 	$rcert->save;
				# }
				$importcount += 1;
			}
		} else {
			$cert = "";
		}

	}

	my $tag = $self->tag;
	say "$importcount intermediate certificates imported ($tag)"

}

1;
