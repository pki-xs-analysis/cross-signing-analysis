
use 5.16.1;
use strict;
use warnings;
use Carp;

use Getopt::ArgParse;
use Text::CSV;

my $ap = Getopt::ArgParse->new_parser(
    prog        => 'perl get_certs.pl file.csv',
    description => 'Get root certificates specified in a Microsoft Trusted Root Certificate Program Participants file (csv encoded).',
    epilog      => '',
);

my $sha1_index = 2;
my $sha256_index = 3;
my $status_index = 4;

if (("2019-02" cmp $ARGV[0]) < 1) {
	# New format starting with February 2019
	$sha1_index = undef;
	$sha256_index = 2;
	$status_index = 3;
}

my $csv = Text::CSV->new({ sep_char => ',' });

my $argv_len = @ARGV;
croak("Please only give one inputfile") unless $argv_len == 1;

my $dir;
my $certcount = 0;
my $reading_header = 1;
my $with_status = 0;
while ( <> ) {

    if ($. == 1) {
        $dir = $ARGV;
        $dir =~ s/.csv//;
        say $dir;
        croak("ERROR: Cannot create directory") if system("mkdir -p $dir");
        croak("ERROR: Erasure of file failed") if system("echo '' > $dir/1.ca");
    }

    $_ =~ s/[[:^ascii:]]/ /g;   # Remove Non-ASCII chars
    croak("Could not parse line $.: $_") unless $csv->parse($_);

    my @linedata = $csv->fields();

    if ($linedata[0] eq "CA Name" or $linedata[0] eq "OrganizationName") {
        croak("Unexpected csv format: index $sha256_index does not contain sha256") if $linedata[$sha256_index] !~ /SHA-256 Thumbprint/;
        if (scalar @linedata >= $status_index and defined($linedata[$status_index])) {
            $with_status = 1;
            croak("Unexpected csv format: index $status_index does not contain status") if $linedata[$status_index] !~ /Status/ and $linedata[$status_index] !~ /Value/;
        }
        $reading_header = 0;
        next;
    }
    if ($reading_header) {
        next;
    }

    my $fingerprint = $linedata[$sha256_index];
    if ($fingerprint =~ /[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]/) {
        $fingerprint = lc $fingerprint;
        $fingerprint =~ s/://g;
    } elsif ($fingerprint =~ /[A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9][A-F,0-9]/) {
        $fingerprint = lc $fingerprint;
    } elsif ($fingerprint eq '') {
        my $fingerprint = $linedata[$sha1_index];
        if ($fingerprint eq '') {
            # intermediate line not representing a cert
            next;
        } else {
            # Fall back to sha 1
            if ($fingerprint =~ /[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]:[A-F,0-9][A-F,0-9]/) {
                $fingerprint = lc $fingerprint;
                $fingerprint =~ s/://g;
            }
        }
    } else {
        croak("Unknown fingerprint format: $fingerprint (full line: $_)");
    }

    my $status;
    if ($with_status) {
        $status = $linedata[$status_index];
        if ($status eq "Active") {
            # do nothing
        } elsif ($status eq "NotBefore") {
            # TODO how to properly handle NotBefore?
            warn "Including cert with status $status: $fingerprint";
        } elsif ($status eq "Disabled" or $status eq "Disable") {
            # TODO how to properly handle Disabled?
            warn "Skipping cert with status $status: $fingerprint";
            next;
        } else {
            croak("Unexpected status value: $status");
        }
    }

    my $cmd_getcertsh = "curl --fail https://crt.sh/?q=$fingerprint";
    my $certsh_out = `$cmd_getcertsh`;
    croak "curl --fail https://crt.sh/?q=$fingerprint failed" if $?;
    foreach my $certsh_line (split /\n/, $certsh_out) {
        if ($certsh_line =~ /Download Certificate: <A href="\?d=([0-9]+)">PEM/) {
            my $id = $1;
            say "id: $id";
            my $cmd_getpem = "curl --fail https://crt.sh/?d=$id | openssl x509 -text -fingerprint -SHA256 | sed '/^\$/d' >> $dir/1.ca";
            my $cert = `$cmd_getpem`;
            croak "$cmd_getpem failed" if $?;
            $certcount += 1;
        }
    }
}

if ($reading_header) {
    croak("Unexpected csv format: Could not find start of certificates");
}

say "Retrieved $certcount certificates.";
