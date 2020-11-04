package CertReader::App::ImportCrtShRevocationsGoogle;

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

use Crypt::OpenSSL::X509;

no if $] >= 5.017011, warnings => 'experimental::smartmatch';

sub run {
	my $self = shift;

	my $importcount = 0;
	my $known_count = 0;
	my $line = 0;

	while ( <> ) {
		$line = $line + 1;
		chomp;  # remove newline from $_
		# say $_;
		my @columns = split /\t/, $_;

		my $expected_column_count = 2;
		if (scalar @columns != $expected_column_count) {
			croak("ERROR: expected $expected_column_count columns but found " . scalar @columns);
		}

		my $crt_sh_cert_id = $columns[0];
		my $entry_type = $columns[1];

		$crt_sh_cert_id = undef if ($crt_sh_cert_id eq '\\N');
		$entry_type = undef if ($entry_type eq '\\N');

		# say "$crt_sh_cert_id: " . (defined $crt_sh_cert_id ? $crt_sh_cert_id: "undef");
		# say "$entry_type: " . (defined $entry_type ? $entry_type: "undef");

		# Create DB entry
		my $entries = CertReader::DB::CrtShRevocationData::GoogleRevoked::Manager->get_crt_sh_revocations_google_revoked(
						query =>
						[
							crt_sh_cert_id => $crt_sh_cert_id,
							entry_type => $entry_type,
						]
					);
		if (scalar @$entries) {
			;  # already known
			say "line $line: Entry already known for GoogleRevoked " . (defined $crt_sh_cert_id ? $crt_sh_cert_id : "n/a");
			$known_count += 1;
		} else {
			my $new_entry = CertReader::DB::CrtShRevocationData::GoogleRevoked->new();
			$new_entry->crt_sh_cert_id($crt_sh_cert_id);
			$new_entry->entry_type($entry_type);

			$new_entry->save;

			say "line $line: Added entry for GoogleRevoked " . (defined $crt_sh_cert_id ? $crt_sh_cert_id : "n/a");
			$importcount += 1;
		}

	}

	say "Finished: imported $importcount lines; Skipped $known_count already known lines.";
	exit(0);
}

1;
