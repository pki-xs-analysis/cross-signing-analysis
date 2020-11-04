package CertReader::CertCache;

use 5.10.1;
use strict;
use warnings;

use Moose::Role;

use Carp;

# cache current list of certificates
has '_certcache' => (
	is => 'rw',
	accessor => 'certcache',
	isa => 'HashRef',
	default => sub { {} },
);

sub getcerts {
	my $self = shift;

	my @out;

	for my $hash ( @_ ) {
		if ( defined($self->certcache->{$hash}) ) {
			push(@out, $self->certcache->{$hash});
		} else {
			my $test = CertReader::DB::Certificate->new(db => $self->db, cert_hash => $hash);
			unless ( $test->load(use_key => 'cert_hash', speculative => 1) ) {
				# this should not happen. In this class anyways.
				croak "Certificate $hash not found";
			}

			$self->certcache->{$hash} = $test;
			push(@out, $test);
		}
	}

	return @out;
}

sub getcerts_sha1 {
	my $self = shift;

	my @out;

	for my $hash ( @_ ) {
		if ( defined($self->certcache->{$hash}) ) {
			push(@out, $self->certcache->{$hash});
		} else {
			my $test = CertReader::DB::Certificate->new(db => $self->db, fingerprint_sha1 => $hash);
			unless ( $test->load(use_key => 'fingerprint_sha1', speculative => 1) ) {
				# this should not happen. In this class anyways.
				croak "Certificate $hash not found";
			}

			$self->certcache->{$hash} = $test;
			push(@out, $test);
		}
	}

	return @out;
}


sub getcerts_from_id {
	my $self = shift;

	my @out;

	for my $id ( @_ ) {
		if ( defined($self->certcache->{$id}) ) { # well, this is kind of dirty, however they really never should mix, so whatever.
			push(@out, $self->certcache->{$id});
		} else {
			my $test = CertReader::DB::Certificate->new(db => $self->db, id => $id);
			unless ( $test->load(speculative => 1) ) {
				# this should not happen. In this class anyways.
				croak "Certificate $id not found";
			}

			$self->certcache->{$test->cert_hash} = $test;
			$self->certcache->{$id} = $test;
			push(@out, $test);
		}
	}

	return @out;
}

1;
