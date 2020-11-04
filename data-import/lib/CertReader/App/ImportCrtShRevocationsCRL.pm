package CertReader::App::ImportCrtShRevocationsCRL;

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

		my $expected_column_count = 5;
		if (scalar @columns != $expected_column_count) {
			croak("ERROR: expected $expected_column_count columns but found " . scalar @columns);
		}

		my $crt_sh_ca_id = $columns[0];
		my $serial_number = $columns[1];
		my $reason_code = $columns[2];
		my $revocation_date = $columns[3];
		my $last_seen_check_date = $columns[4];

		$crt_sh_ca_id = undef if ($crt_sh_ca_id eq '\\N');
		$serial_number = undef if ($serial_number eq '\\N');
		$reason_code = undef if ($reason_code eq '\\N');
		$revocation_date = undef if ($revocation_date eq '\\N');
		$last_seen_check_date = undef if ($last_seen_check_date eq '\\N');

		# say "$crt_sh_cert_id: " . (defined $crt_sh_cert_id ? $crt_sh_cert_id : "undef");
		# say "$disallowed_hash: " . (defined $disallowed_hash ? $disallowed_hash : "undef");

		my $serial_number_formatted = defined $serial_number? (pack 'H*', (substr $serial_number, 3)) : $serial_number;

		# Create DB entry
		my $entries = CertReader::DB::CrtShRevocationData::CRLrevoked::Manager->get_crt_sh_revocations_crl_revoked(
						query =>
						[
							crt_sh_ca_id => $crt_sh_ca_id,
							serial_number => $serial_number_formatted,
						]
					);
		if (scalar @$entries) {
			;  # already known
			say "line $line: Entry already known for CRL ($crt_sh_ca_id, $serial_number)";
			$known_count += 1;
		} else {

			my $new_entry = CertReader::DB::CrtShRevocationData::CRLrevoked->new();
			$new_entry->crt_sh_ca_id($crt_sh_ca_id);
			$new_entry->serial_number($serial_number_formatted);
			$new_entry->reason_code($reason_code);
			$new_entry->revocation_date($revocation_date);
			$new_entry->last_seen_check_date($last_seen_check_date);

			$new_entry->save;

			say "line $line: Added entry for CRL ($crt_sh_ca_id, $serial_number)";
			$importcount += 1;
		}

	}

	say "Finished: imported $importcount lines; Skipped $known_count already known lines.";
	exit(0);
}

1;
