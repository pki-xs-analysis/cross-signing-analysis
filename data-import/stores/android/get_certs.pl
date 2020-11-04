
use 5.16.1;
use strict;
use warnings;
use Carp;

use Getopt::ArgParse;
use Switch;

use constant {
    PRE_ANDROID_7 => 1,
    ANDROID_7_AND_LATER => 2,
};

my $ap = Getopt::ArgParse->new_parser(
    prog        => 'Android Root Cert Grabber',
    description => 'Get root certificates of specific android version.',
    epilog      => '',
);

$ap->add_arg('--tag', '-t', type => 'Scalar', required => 1, help => 'Android tag/branch name for which certificates should be obtained. See e.g., https://source.android.com/setup/start/build-numbers');
my $ns = $ap->parse_args;
my $tag = $ns->tag;

if ($tag =~ /^[1-9]/) {
    $tag = "android-" . $tag;
     say "Detected tag starting with number. Will get certificates for tag $tag";
}

my $version;
my $dir_prefix = "";
if ($tag =~ /^android-[0-6]./) {
    $version = PRE_ANDROID_7;
} elsif ($tag =~ /^android-[7-9]./ || $tag =~ /^android-[1-9]0./ || $tag =~ /^android-q./) {
    $version = ANDROID_7_AND_LATER;
    if ($tag =~ /^android-q./) {
        $dir_prefix = "10.0.0_r000_";
    }
} else {
    croak("Unknown historical context for $tag.")
}

my $url;
# See https://android.googlesource.com/platform/libcore/+/2e2dbe9a15b1f41c311f39aebbb2a843c81994e7
# and https://android.googlesource.com/platform/libcore/+log/android-7.0.0_r1/luni/src/main/files
switch ($version) {
    case PRE_ANDROID_7          { $url = "https://android.googlesource.com/platform/libcore/+archive/$tag/luni/src/main/files/cacerts.tar.gz" }
    case ANDROID_7_AND_LATER    { $url = "https://android.googlesource.com/platform/system/ca-certificates/+archive/$tag/files.tar.gz" }
    else                        { croak("unknown historical context for $tag") }
}

my $dir = $tag;
$dir =~ s/android-//;   # just to keep up with already included naming structure
$dir = $dir_prefix . $dir;
say "Will fetch certificates from $url to $dir";

croak("ERROR: Cannot create directory") if system("mkdir -p $dir");
croak("ERROR: Download & Extract failed") if system("curl $url | tar -xzf - -O > $dir/1.ca");
