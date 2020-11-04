package Zgrab::Log::ParseLine;

use 5.14.1;
use strict;
use warnings;

use autodie;
use Carp;
use Scalar::Util qw/openhandle/;

use Data::Dumper;  # debugging

use Moose;

has 'data' => (
    is => 'ro',
    isa => 'HashRef',
    required => '1',
    documentation => "Data as returned by Zgrab::Log::Parse::getLine",
);

has 'sanitycheck_format' => (
    is => 'rw',
    isa => 'Bool',
    required => '1',
    default => 1,
    documentation => "Check if the json format deviates from expectations",
);

sub get_timestamp {
    my $self = shift;
    my $r_data = $self->data;

    return $r_data->{timestamp};
}

sub has_certificate_entry {
    my $cur = shift;
    my $path = shift;
    my $found = 0;
    my $found_paths = "";

    if ( ref($cur) eq "HASH" ) {
        foreach (keys %$cur) {
            if ($_ =~ /certificate/) {
                return (1, "$path.$_");
            } else {
                # say "$path.$_";
                my ($res, $res_path) = has_certificate_entry($cur->{$_}, "$path.$_");
                if ($res) {
                    # return ($res, $res_path);
                    $found = 1;
                    $found_paths .= ";" if !($found_paths eq "");
                    $found_paths .= "$res_path";
                }
            }
        }
    } elsif (ref($cur) eq "ARRAY") {
        my $index = -1;
        foreach (@$cur) {
            $index += 1;
            # say "$path.[$index]";
            # say Dumper($_);
            my ($res, $res_path) = has_certificate_entry($_, "$path.[$index]");
            if ($res) {
                # return ($res, $res_path);
                $found = 1;
                $found_paths .= ";" if !($found_paths eq "");
                $found_paths .= "$res_path";
            }
        }
    }

    return $found, $found_paths;
}

sub get_tls {
    my $self = shift;
    my $r_data = $self->data;

    my @ret;
    my $tls_entry;

    # censys format
    $tls_entry = $r_data->{data}{tls};
    push @ret, $tls_entry if (keys %$tls_entry);
    if (scalar @ret == 0) {
        # zgrab format (comsys data - non-redirect)
        $tls_entry = $r_data->{data}{http}{response}{request}{tls_handshake};
        push @ret, $tls_entry if (keys %$tls_entry);
    }
    if (scalar @ret == 0) {
        # zgrab format (comsys data - redirect chain)
        my $chain = $r_data->{data}{http}{redirect_response_chain};
        if (defined($chain)) {
            foreach (@$chain) {
                $tls_entry = $_->{request}{tls_handshake};
                push @ret, $tls_entry if (keys %$tls_entry);
            }
        }
    }
    # TODO other locations

    # Sanity check
    # No tls data found; Check if some key is likely to contain a certificate
    # and we simply miss a proper implementation for this case
    if ($self->sanitycheck_format and scalar @ret == 0) {
        my ($res, $path) = has_certificate_entry($r_data, "");
        croak ("unexpected path: $path") if $res;
    }

    croak("no tls data") if (scalar @ret == 0);

    return \@ret;
}

sub get_servercerts {
    my $self = shift;
    my $r_tlsdata = $self->get_tls();

    my @server_certificates;
    my $cert;
    foreach (@$r_tlsdata) {
        $cert = $_->{server_certificates}{certificate};
        push @server_certificates, $cert if defined($cert);
    }

    return \@server_certificates;
}

sub get_certchains {
    my $self = shift;
    my $r_tlsdata = $self->get_tls();

    my @chains;
    my $chain;
    foreach (@$r_tlsdata) {
        $chain = $_->{server_certificates}{chain};
        push @chains, $chain if defined($chain);
    }

    return \@chains;
}

sub get_error {
    my $self = shift;
    my $r_data = $self->data;
    return $r_data->{error};
}

sub get_errorcomponent {
    my $self = shift;
    my $r_data = $self->data;
    return $r_data->{error_component};
}

1;
