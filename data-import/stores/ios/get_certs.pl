
use 5.16.1;
use strict;
use warnings;
use Carp;

use Getopt::ArgParse;
use Switch;
use POSIX qw(strftime);

my $ap = Getopt::ArgParse->new_parser(
    prog        => 'iOS Root Cert Grabber',
    description => 'Get root certificates of specific ios version.',
    epilog      => '',
);

$ap->add_arg('--version', '-t', type => 'Scalar', required => 0, help => 'iOS version for a fresh download of apples support database (example: --version 11)');
$ap->add_arg('--file', '-f', type => 'Scalar', required => 0, help => 'Read certificates from html sourcefile instead of downloading the current webpage');
my $ns = $ap->parse_args;
my $version = $ns->version;
my $file = $ns->file;

croak("Requiring one of --version or --file") if (!(defined($version) || defined($file)));

my $html;
my $cafile;
if (defined $file) {
	my $dir = `dirname $file`;
	chomp $dir;
	my $basename = `basename -s .html $file`;
	chomp $basename;
	$cafile = "$dir/$basename.ca";

	open(my $fh, '<', $file) or die "Could not open file '$file' $!";
	read $fh, $html, -s $fh;
	close $fh;
} else {
	my $apple_url;
	switch($version) {
	    case 12     { $apple_url = "https://support.apple.com/en-us/HT209144" }
	    case 11     { $apple_url = "https://support.apple.com/en-us/HT208125" }
	    case 10	{ $apple_url = "https://support.apple.com/en-us/HT207177" }
	    case 9	{ $apple_url = "https://support.apple.com/en-us/HT205205" }
	    case 8	{ $apple_url = "https://support.apple.com/en-us/HT205214" }
	    # case 7	{ $apple_url = "https://support.apple.com/en-us/HT203065" } # different format, need to write parser
	    # case 6	{ $apple_url = "https://support.apple.com/en-us/HT201388" } # different format, need to write parser
	    # case 5	{ $apple_url = "https://support.apple.com/en-us/HT201388" } # different format, need to write parser
	    else        { croak("Unknown URL for iOS version $version. Please update script.") }
	}

	$html = `curl --fail $apple_url`;
	croak "curl --fail $apple_url failed" if $?;

	my $datestring = strftime "%F", localtime();
	my $dir = "ios" . $version;
	$cafile = "$dir/$datestring.ca";
	croak("ERROR: Cannot create directory") if system("mkdir -p $dir");

	# save the source file for later reference
	my $htmlfile = "$dir/$datestring.html";
	open(my $fh, '>', $htmlfile) or die "Could not open file '$htmlfile' $!";
	print $fh $html;
	close $fh;
}

croak("ERROR: Erasure of ca file $cafile failed") if system("echo '' > $cafile");

my $readcerts = 0;
my $certcount = 0;
foreach my $line (split /\n/, $html) {
    $readcerts = 1 if $line =~ /<h2>Trusted certificates/;
    $readcerts = 0 if $line =~ /<h2>Always Ask certificates/;
    $readcerts = 0 if $line =~ /<h2>Blocked certificates/;

    if ($readcerts) {
        if ($line =~ /[A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9] [A-F,0-9][A-F,0-9]/) {

            my $fingerprint_sha256 = $line;
            $fingerprint_sha256 =~ s/<td>//;
            $fingerprint_sha256 =~ s/<\/td>//;
            $fingerprint_sha256 =~ s/&nbsp;//;
            $fingerprint_sha256 =~ s/<br>//;
            $fingerprint_sha256 =~ s/ //g;
            $fingerprint_sha256 = lc $fingerprint_sha256;
            say $fingerprint_sha256;

            my $cmd_getcertsh = "curl --fail https://crt.sh/?q=$fingerprint_sha256";
            my $certsh_out = `$cmd_getcertsh`;
            croak "curl --fail https://crt.sh/?q=$fingerprint_sha256 failed" if $?;
            my $certcount_old = $certcount;
            foreach my $certsh_line (split /\n/, $certsh_out) {
                if ($certsh_line =~ /Download Certificate: <A href="\?d=([0-9]+)">PEM/) {
                    my $id = $1;
                    say "id: $id";
                    my $cmd_getpem = "curl --fail https://crt.sh/?d=$id | openssl x509 -text -fingerprint -SHA256 | sed '/^\$/d' >> $cafile";
                    my $cert = `$cmd_getpem`;
                    croak "$cmd_getpem failed" if $?;
                    $certcount += 1;
                }
            }

            if(!($certcount_old < $certcount)) {
                croak("Found no certificate with fingerprint $fingerprint_sha256");
            }
        }
    }
}

say "Retrieved $certcount certificates.";
