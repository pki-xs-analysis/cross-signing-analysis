package CertReader::CA::Chain;

use 5.16.1;

use strict;
use warnings;
use Carp;

use Moose;

use Date::Parse;

has 'rid' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
);

has 'store' => (
	is => 'rw',
	isa => 'Crypt::OpenSSL::X509::Rootstore',
	required => 1,
);

# has 'openssl' => (
# 	is => 'rw',
# 	isa => 'ArrayRef',
# 	required => 1
# );

has 'cert_ids' => (
    is => 'rw',
    isa => 'ArrayRef',
    required => 1
);

has 'ca_chain_id' => (
    is => 'rw',
    isa => 'Int',
    required => 0,
);

sub contains_cert {
    my ($self, $cert) = @_;

    for my $ccert_id (@{$self->cert_ids}) {
        return 1 if ($ccert_id == $cert->id);
    }
    return 0;
}

sub set_cache_certs_by_id {
    my ($self, $certs_by_id) = @_;
    $self->{'certs_by_id'} = $certs_by_id;
}

sub _get_cert {
    my ($self, $cert_id) = @_;

    my $cert;
    if (defined $self->{'certs_by_id'}) {
        if (exists $self->{'certs_by_id'}->{$cert_id}) {
            $cert = $self->{'certs_by_id'}->{$cert_id};
        }
    }

    if (! defined($cert)) {
        say "WARNING: using uncached cert $cert_id";  # TODO debug
        $cert = CertReader::DB::Certificate->new(id => $cert_id);
        $cert->load();
    }

    return $cert;
}

sub certs {
    my ($self) = @_;
    my @certs;
    for my $ccert_id (@{$self->cert_ids}) {
        my $cert = $self->_get_cert($ccert_id);
        push(@certs, $cert);
    }

    return \@certs;
}

sub openssl {
    my $self = shift;
    my $openssl = [];
    for my $cert (@{$self->certs}) {
        push(@$openssl, $cert->openssl);
    }
    return $openssl;
}

sub length {
    my $self = shift;
    return scalar @{$self->cert_ids};
}

sub get_path {
    # return the path as string of cert ids, starting with the root
    my $self = shift;
    return join('.', reverse @{$self->cert_ids});
}

sub get_validity_period {
    my $self = shift;

    if (defined($self->{'ts_not_before'}) and defined($self->{'ts_not_after'})) {
        return ($self->{'ts_not_before'}, $self->{'ts_not_after'});
    }

    my $chain_ts_not_before;
    my $chain_ts_not_after;
    for my $cert (@{$self->certs}) {
        my $cert_ts_not_before = str2time($cert->not_before, "GMT");
        if (defined($chain_ts_not_before)) {
            $chain_ts_not_before = $cert_ts_not_before if $chain_ts_not_before < $cert_ts_not_before;
        } else {
            $chain_ts_not_before = $cert_ts_not_before;
        }

        my $cert_ts_not_after = str2time($cert->not_after, "GMT");
        if (defined($chain_ts_not_after)) {
            $chain_ts_not_after = $cert_ts_not_after if $cert_ts_not_after < $chain_ts_not_after;
        } else {
            $chain_ts_not_after = $cert_ts_not_after;
        }
    }

    $self->{'ts_not_before'} = $chain_ts_not_before;
    $self->{'ts_not_after'} = $chain_ts_not_after;
    return $self->{'ts_not_before'}, $self->{'ts_not_after'};
}

1;
