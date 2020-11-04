package CertReader::CA::ValidChain;

use 5.16.1;

use strict;
use warnings;
use Carp;

use Moose;

use List::Util qw[min max];

has 'openssl' => (
	is => 'rw',
	isa => 'ArrayRef',
	required => 1
);

has 'certs' => (
    is => 'rw',
    isa => 'ArrayRef',
    required => 1
);

has 'not_before' => (
    is => 'rw',
    isa => 'Str | Undef',
    required => 1,
    default => undef
);

has 'not_after' => (
    is => 'rw',
    isa => 'Str | Undef',
    required => 1,
    default => undef
);

has 'ca_chain_id' => (
    is => 'rw',
    isa => 'Int',
    required => 1,
);

sub contains_cert {
    my ($self, $cert) = @_;

    for my $ccert (@{$self->certs}) {
        return 1 if ($ccert == $cert);
    }
    return 0;
}

sub length {
    my $self = shift;
    return scalar @{$self->certs};
}

sub get_path {
    # return the path as string of cert ids, starting with the root
    my $self = shift;

    my @c = map {$_->id} @{$self->certs};
    my $path = join('.', reverse @c);

    return $path;
}

sub get_pathlen {
    # return the pathlen for the full chain, i.e., the pathlen value considered
    # to determine if the "leaf" of the chain can issue a certificate
    my $self = shift;

    my $pathlen = undef;

    my @certs_starting_with_root = reverse(@{$self->certs});
    my $rootcert = shift @certs_starting_with_root; # pathlen of root is ignored during validation
    for my $cert (@certs_starting_with_root) {
        if (defined $pathlen) {
            $pathlen = $pathlen - 1;
        }

        my $cert_pathlen = $cert->get_pathlen;
        if (defined $cert_pathlen) {
            if (defined $pathlen) {
                $pathlen = min($pathlen, $cert_pathlen);
            } else {
                $pathlen = $cert_pathlen;
            }
        }
    }

    return $pathlen;
}

sub can_issue_based_on_pathlen {
    my $self = shift;

    my $pathlen = $self->get_pathlen;
    if (not defined($pathlen)) {
        return 1;
    }
    if ($pathlen >= 0) {
        return 1;
    }
    return 0;
}


1;
