# dirty script to prevent that we read a certificate twice.

use 5.10.1;
use autodie;

my $source = shift @ARGV;

die("Not a number") unless ($source =~ m/^\d+$/);

for my $file ( @ARGV ) {
	exit(0) if (-e "stop");
	die("Unknown file $file") unless $file =~ s/((\.log)?\.[gx]z)$//; # allow for xz and gz

	my $suffix = $1;

	next if ( -e "$file.readcert_paper" );
	next if ( -e "$file.log.readcert_paper" );

	say "Trying to read ".$file.$suffix;
	say "mx-run -Ilib CertReader::App::Readcertmap --source $source --tablepostfix full ".$file.$suffix;

	my $ret = system("mx-run -Ilib CertReader::App::Readcertmap --source $source --tablepostfix full ".$file.$suffix);

	say "finished $file$suffix";

	if ( ($? >> 8) != 0 ) {
		die("Child exited with wrong signal for $file.$suffix");
	}

	# mark as parsed
	open (my $fh, "> $file.readcert_paper");
	close $fh;
}

exit 0;
