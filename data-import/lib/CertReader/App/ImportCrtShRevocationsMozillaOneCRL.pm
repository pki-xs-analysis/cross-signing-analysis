package CertReader::App::ImportCrtShRevocationsMozillaOneCRL;

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

		my $expected_column_count = 10;
		if (scalar @columns != $expected_column_count) {
			croak("ERROR: expected $expected_column_count columns but found " . scalar @columns);
		}

		my $crt_sh_cert_id = $columns[0];
		my $crt_sh_issuer_ca_id = $columns[1];
		my $issuer_name = $columns[2];
		my $last_modified = $columns[3];
		my $serial_number = $columns[4];
		my $created = $columns[5];
		my $bug_url = $columns[6];
		my $summary = $columns[7];
		my $subject_name = $columns[8];
		my $not_after = $columns[9];

		$crt_sh_cert_id = undef if ($crt_sh_cert_id eq '\\N');
		$crt_sh_issuer_ca_id = undef if ($crt_sh_issuer_ca_id eq '\\N');
		$issuer_name = undef if ($issuer_name eq '\\N');
		$last_modified = undef if ($last_modified eq '\\N');
		$serial_number = undef if ($serial_number eq '\\N');
		$created = undef if ($created eq '\\N');
		$bug_url = undef if ($bug_url eq '\\N');
		$summary = undef if ($summary eq '\\N');
		$subject_name = undef if ($subject_name eq '\\N');
		$not_after = undef if ($not_after eq '\\N');

		# say "crt_sh_cert_id: " . (defined $crt_sh_cert_id ? $crt_sh_cert_id : "undef");
		# say "crt_sh_issuer_ca_id: " . (defined $crt_sh_issuer_ca_id ? $crt_sh_issuer_ca_id : "undef");
		# say "issuer_name: " . (defined $issuer_name ? $issuer_name : "undef");
		# say "last_modified: " . (defined $last_modified ? $last_modified : "undef");
		# say "serial_number: " . (defined $serial_number ? $serial_number : "undef");
		# say "created: " . (defined $created ? $created : "undef");
		# say "bug_url: " . (defined $bug_url ? $bug_url : "undef");
		# say "summary: " . (defined $summary ? $summary : "undef");
		# say "subject_name: " . (defined $subject_name ? $subject_name : "undef");
		# say "not_after: " . (defined $not_after ? $not_after : "undef");
		# say "";

		my $issuer_name_formatted = defined $issuer_name ? (pack 'H*', (substr $issuer_name, 3)) : $issuer_name;
		my $serial_number_formatted = defined $serial_number ? (pack 'H*', (substr $serial_number, 3)) : $serial_number;
		my $subject_name_formatted = defined $subject_name ? (pack 'H*', (substr $subject_name, 3)) : $subject_name;

		# Create DB entry
		my $entries = CertReader::DB::CrtShRevocationData::MozillaOneCRL::Manager->get_crt_sh_revocations_mozilla_onecrl(
						query =>
						[
							crt_sh_cert_id => $crt_sh_cert_id,
							crt_sh_issuer_ca_id => $crt_sh_issuer_ca_id,
							issuer_name => $issuer_name_formatted,
							last_modified => $last_modified,
							serial_number => $serial_number_formatted,
							created => $created,
							bug_url => $bug_url,
							summary => $summary,
							subject_name => $subject_name_formatted,
							not_after => $not_after,
						]
					);
		if (scalar @$entries) {
			;  # already known
			say "line $line: OneCRL revocation already known for crt.sh certificate " . (defined $crt_sh_cert_id ? $crt_sh_cert_id : "n/a");
			$known_count += 1;
		} else {

			my $new_crt_sh_onecrl_entry = CertReader::DB::CrtShRevocationData::MozillaOneCRL->new();
			$new_crt_sh_onecrl_entry->crt_sh_cert_id($crt_sh_cert_id);
			$new_crt_sh_onecrl_entry->crt_sh_issuer_ca_id($crt_sh_issuer_ca_id);
			$new_crt_sh_onecrl_entry->issuer_name($issuer_name_formatted);
			$new_crt_sh_onecrl_entry->last_modified($last_modified);
			$new_crt_sh_onecrl_entry->serial_number($serial_number_formatted);
			$new_crt_sh_onecrl_entry->created($created);
			$new_crt_sh_onecrl_entry->bug_url($bug_url);
			$new_crt_sh_onecrl_entry->summary($summary);
			$new_crt_sh_onecrl_entry->subject_name($subject_name_formatted);
			$new_crt_sh_onecrl_entry->not_after($not_after);

			$new_crt_sh_onecrl_entry->save;

			say "line $line: Added OneCRL revocation for crt.sh certificate " . (defined $crt_sh_cert_id ? $crt_sh_cert_id : "n/a");
			$importcount += 1;
		}

	}

	say "Finished: imported $importcount lines; Skipped $known_count already known lines.";
	exit(0);
}

1;
