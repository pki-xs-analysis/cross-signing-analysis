use 5.10.1;
use autodie;

# create all the .statistics_new files
# run with something akinn to:
# find /xa/ssl/dropboxes/ -name "ssl_conn*.xz" -print0 | xargs -0 -n5 -P10 perl ./readconns.pl

for my $file ( @ARGV ) {
	exit(0) if (-e "stop");
	die("Unknown file $file") unless $file =~ s/((\.log\.xz)|(\.log\.bz2)|(\.gz)|(\.xz))$//;

	my $suffix = $1;

	next if ( -e "$file.statistics_new" );
	next if ( -e "$file.log.statistics_new" );

	say "Trying to read ".$file.$suffix;
	my $cmd = "mx-run -Ilib CertReader::App::Readseen --disableseenfull --nodb --fileextension .statistics_new ".$file.$suffix;
	say $cmd;

	my $ret = system($cmd);

	if ( ($? >> 8) != 0 ) {
		die("Child exited with wrong signal for $file");
	}
}
