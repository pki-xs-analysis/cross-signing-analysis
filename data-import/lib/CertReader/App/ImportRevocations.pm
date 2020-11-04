package CertReader::App::ImportRevocations;

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

use CertReader::DB::RevokedCerts;

use Crypt::OpenSSL::X509;
use DateTime::Format::ISO8601;
use File::Basename;

use lib './stores/mozilla';
use MozillaTruststoreRevisions;

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

sub ff_tag_sort {
    # return -1 if $a is earlier release, 1 else, 0 if they are the same
    my @as = split /_/, $a;
    my @bs = split /_/, $b;
    my $i = 0;
    while(1) {
        return 0 if $as[$i] eq "RELEASE" and $bs[$i] eq "RELEASE";
        return -1 if $as[$i] eq "RELEASE";
        return 1 if $bs[$i] eq "RELEASE";

        if ( $as[$i] =~ /^\d+$/ and $bs[$i] =~ /^\d+$/ ) {
            return -1 if $as[$i] < $bs[$i];
            return 1 if $as[$i] > $bs[$i];
        } else {
            # TODO works for 1a1 vs. 1a2 but not for 1a1 vs. 1b1 or 1a1 vs. 1a10
            my $ret = $as[$i] cmp $bs[$i];
            return $ret if $ret != 0;
        }

        $i += 1;
    }
}

sub microsoft_tag_sort {
    return $a cmp $b;
}

sub android_tag_sort {
    my ($a_v, $a_r) = split(/_r/, $a);
    my ($b_v, $b_r) = split(/_r/, $b);
    my ($a_major, $a_minor, $a_sub) = split(/\./, $a_v);
    $a_sub = 0 if !defined($a_sub);
    my ($b_major, $b_minor, $b_sub) = split(/\./, $b_v);
    $b_sub = 0 if !defined($b_sub);

    if ($a_major != $b_major) {
        if (int($a_major) > int($b_major)) {
            return 1;
        } else {
            return -1;
        }
    } elsif ($a_minor != $b_minor) {
        if (int($a_minor) > int($b_minor)) {
            return 1;
        } else {
            return -1;
        }
    } elsif ($a_sub != $b_sub) {
        if (int($a_sub) > int($b_sub)) {
            return 1;
        } else {
            return -1;
        }
    } elsif ($a_r != $b_r) {
        if (int($a_r) > int($b_r)) {
            return 1;
        } else {
            return -1;
        }
    }
}

sub igtf_tag_sort {
    my $an = (split(/-/, $a))[-1];
    my $bn = (split(/-/, $b))[-1];
    my ($a_major, $a_minor) = split(/\./, "$an");
    my ($b_major, $b_minor) = split(/\./, "$bn");
    if ($a_major != $b_major) {
        if (int($a_major) > int($b_major)) {
            return 1;
        } else {
            return -1;
        }
    } elsif ($a_minor != $b_minor) {
        if (int($a_minor) > int($b_minor)) {
            return 1;
        } else {
            return -1;
        }
    } else {
        croak("Unexpected format $a vs. $b");
    }
}

sub run {
    my $self = shift;

    my $revisions;
    my $revision_to_filename;
    my $revision_to_revisionname;
    my $sortfunction;
    if ($self->tag eq "mozilla") {
        $revisions = MozillaTruststoreRevisions->revisions;
        $revision_to_filename = sub { my $rev = shift; return "./stores/mozilla/$rev/ca-bundle.crt" };
        $sortfunction = \&ff_tag_sort;
        $revision_to_revisionname = sub { return shift; };
    } elsif ($self->tag eq "microsoft") {
        $revisions = {};
        foreach (glob("./stores/ms-ca/*.csv")) {
            my ($filename, $dirs, $suffix) = fileparse($_, ".csv");
            $revisions->{$filename} = {};
        }
        $revision_to_filename = sub { my $rev = shift; return "./stores/ms-ca/$rev/1.ca" };
        $sortfunction = \&microsoft_tag_sort;
        $revision_to_revisionname = sub { return "microsoft-" . shift; };
    } elsif ($self->tag eq "android") {
        $revisions = {};
        foreach (glob("./stores/android/*/1.ca")) {
            my $rev = (split(/\//, $_))[-2];
            $revisions->{$rev} = {};
        }
        $revision_to_filename = sub { my $rev = shift; return "./stores/android/$rev/1.ca" };
        $sortfunction = \&android_tag_sort;
        $revision_to_revisionname = sub { return "android-" . shift; };
    } elsif ($self->tag eq "grid-igtf-classic" or $self->tag eq "grid-igtf-iota" or $self->tag eq "grid-igtf-mics" or $self->tag eq "grid-igtf-slcs") {
        $revisions = {};
        my $subtype = $self->tag;
        $subtype =~ s/grid-igtf-//;
        foreach (glob("./stores/grid/*$subtype*.ca")) {
            my ($filename, $dirs, $suffix) = fileparse($_, ".ca");
            $revisions->{$filename} = {};
        }
        $revision_to_filename = sub { my $rev = shift; return "./stores/grid/$rev.ca" };
        $sortfunction = \&igtf_tag_sort;
        $revision_to_revisionname = sub { my $rev = shift; $rev =~ s/igtf-preinstalled-bundle-//; return "grid-igtf-$rev"; };
    } else {
        croak ("Unexptected tag $self->{tag}");
    }

    my $prev;
    for my $rev (sort $sortfunction keys %$revisions) {
        my $revisionname = $revision_to_revisionname->($rev);
        say "-- " . $revisionname;

        # Gather up certs for comparison with previous version; Add certs if not in DB
        $revisions->{$rev}->{certs} = {};
        my $file = $revision_to_filename->($rev);
        open(my $cas, "<", $file);
        my $cert;
        while(<$cas>) {
            if (/BEGIN C/../END C/ ) {
                $cert .= $_;
                if ( /END C/ ) {
                    # TODO No error on non-pem format
                    my $id = $self->readsinglecert($cert, Crypt::OpenSSL::X509::FORMAT_PEM);

                    my $rcert = CertReader::DB::Certificate->new(id => $id);
                    croak ("new certificate not found?") unless ( $rcert->load(speculative => 1) );
                    $revisions->{$rev}->{certs}->{$rcert->fingerprint_sha256} = $rcert;

                    $cert = "";
                }
            } else {
                $cert = "";
            }
        }
        my $totalcount = scalar (keys %{$revisions->{$rev}->{certs}});
        say "$revisionname total certs: $totalcount";

        say "----- Revoked certs";
        # Check which certs have been removed and store info in DB
        my $revoked_count = 0;
        my $revoked_new = 0;
        if (defined $prev) {
            for my $prev_sha256 (sort keys %{$revisions->{$prev}->{certs}}) {
                if (!defined($revisions->{$rev}->{certs}->{$prev_sha256})) {

                    my $cert = $revisions->{$prev}->{certs}->{$prev_sha256};
                    my $test = CertReader::DB::RevokedCerts->new(certificate => $cert->id);

                    if ( $test->load(use_key => 'certificate', speculative => 1) ) {
                        push(@{$test->flags}, $revisionname) unless ($revisionname ~~ @{$test->flags});
                        $test->save;
                    } else {
                        $test->flags([$revisionname]);
                        $test->save;
                        $revoked_new += 1;
                    }

                    say "Revoked cert: $prev_sha256";
                    $revoked_count += 1;
                }
            }
        }

        say "----- New certs";
        my $new_count = 0;
        if (defined $prev) {
            for my $cur_sha256 (sort keys %{$revisions->{$rev}->{certs}}) {
                if (!defined($revisions->{$prev}->{certs}->{$cur_sha256})) {
                    say "New cert: $cur_sha256";
                    $new_count += 1;
                }
            }
        }
        say "-----";

        say "$rev revoked certs: $revoked_count";
        say "$rev previously unknown revocations: $revoked_new";
        say "$rev new certs: $new_count";

        say "";
        $prev = $rev;
    }

}

1;
