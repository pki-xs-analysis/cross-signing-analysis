
use 5.16.1;
use strict;
use warnings;
use Carp;

use DateTime::Format::ISO8601;

use lib '.';
use MozillaTruststoreRevisions;

my $revisions = MozillaTruststoreRevisions->revisions;

for my $rev (sort keys %$revisions) {
    say $rev;
    # my $dt = $revisions->{$rev}->{date};
    # my $dt_formatted = $dt->iso8601();
    # my $dir = "$dt_formatted";
    my $dir = "$rev";
    # my $file = "$dt_formatted-$rev-certdata.txt";
    my $file = "$rev-certdata.txt";
    my $path = "$dir/$file";
    say "-- " . $path;

    my $cmd = "curl --fail --silent --show-error --create-dirs --output $path https://hg.mozilla.org/releases/mozilla-release/raw-file/$rev/security/nss/lib/ckfw/builtins/certdata.txt";
    my $out = `$cmd`;
    croak "$cmd failed" if $?;

    $cmd = "cd $dir && ln -s $file certdata.txt && perl ../mk-ca-bundle.pl -n -u && cd ..";
    say `$cmd`;
    croak "$cmd failed" if $?;
    say "";
}
