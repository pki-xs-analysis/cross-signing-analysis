package CertReader::App::ImportCrtShCertificates;

# Import a root-store into the db and tag it correctly

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

# has 'tag' => (
# 	is => 'rw',
# 	isa => 'Str',
# 	required => 1,
# 	documentation => 'Tag rootstore with...',
# );

has 'cacerts' => (
	is => 'ro',
	isa => 'Bool',
	required => '0',
	default => '0',
	documentation => "Only store CA certificates in the database.",
);

sub run {
	my $self = shift;

	my $importcount = 0;
	my $import_crt_sh_ids = 0;
	my $line = 0;

	while ( <> ) {
		$line = $line + 1;
		my @columns = split /\t/, $_;

		my $expected_column_count = 3;
		if (scalar @columns != $expected_column_count) {
			croak("ERROR: expected $expected_column_count columns but found " . scalar @columns);
		}

		my $crt_sh_id = $columns[0];
		my $crt_sh_issuer_ca_id = $columns[1];

		my $cert_bytea = $columns[2];
		my $cert_bytea_stripped = substr $cert_bytea, 3;  # Remove leading "\\x"
		my $cert_der = pack 'H*', $cert_bytea_stripped;

		# my $c = Crypt::OpenSSL::X509->new_from_string($cert_der, Crypt::OpenSSL::X509::FORMAT_ASN1);
		# say "id: " . $crt_sh_id;
		# say "issuer_ca_id: " . $crt_sh_issuer_ca_id;
		# # say "bytea: " . $cert_bytea;
		# # say "crt_bin: " . $crt_bin;
		# say "subject: " . $c->subject;
		# say "issuer: " . $c->issuer;
		# say "hash: " . $c->fingerprint_sha256;
		# say "";


		# add cert to DB
		my $id = $self->readsinglecert($cert_der, Crypt::OpenSSL::X509::FORMAT_ASN1);

		# Create CrtShCertificate entry
		my $new_crt_sh_cert = CertReader::DB::CrtShCertificate->new(crt_sh_id => $crt_sh_id);
		if ( $new_crt_sh_cert->load( speculative => 1) ) {
			;  # already known
		} else {
			$new_crt_sh_cert->crt_sh_issuer_ca_id($crt_sh_issuer_ca_id);
			$new_crt_sh_cert->certificate_id_local($id);

			$new_crt_sh_cert->save;
		}

		# Sanity checks
		my $db_certificate = CertReader::DB::Certificate->new(id => $id);
		croak("certificate not found in DB") unless ( $db_certificate->load(speculative => 1) );
		my $db_crt_sh_cert = CertReader::DB::CrtShCertificate->new(crt_sh_id => $crt_sh_id);
		croak("crt.sh cert not found in DB") unless ( $db_crt_sh_cert->load(speculative => 1) );

		say "line $line: Added certificate $id (crt.sh id: $crt_sh_id)";
		$importcount += 1;

	}

	say "Finished: imported $importcount certificates"

}

1;
