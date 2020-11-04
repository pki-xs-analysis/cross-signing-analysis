package CertReader::ORM;

use 5.10.1;
use strict;
use warnings;

use Carp;

use Moose::Role;

use CertReader::DB;
use CertReader::DB::Certificate;
use CertReader::DB::CertificateExtension;
use CertReader::DB::CertificateValidity;
use CertReader::DB::Chain;
use CertReader::DB::SeenStats;
use CertReader::DB::VerifyTree;
use CertReader::DB::RootCerts;
use CertReader::DB::CrossSignCandidate;
use CertReader::DB::CAactor;
use CertReader::DB::CertificateRelation;
use CertReader::DB::CArelation;
use CertReader::DB::CrtShCertificate;
use CertReader::DB::CrtShRevocationData;
use CertReader::DB::CaChain;
use CertReader::DB::ValidationStateCertificate;
use CertReader::DB::ValidationStateRootcert;
use CertReader::DB::RootstoreVersion;

has 'tablepostfix' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	documentation => "Postfix to append to table names (default: full)",
	default => 'full',
);

has '_db' => (
	is => 'rw',
	required => 0,
	accessor => 'db',
	lazy => 1,
	builder => '__initdb',
);

has 'domain' => (
	is => 'rw',
	isa => 'Str',
	required => 0,
	documentation => "Current database domain",
);

sub __initdb {
	my $self = shift;

	$self->set_tablenames($self->tablepostfix);
	if ( defined($self->domain) ) {
		CertReader::DB->default_domain($self->domain);
	}

	my $db = CertReader::DB->new;

	$db->dbh->{pg_enable_utf8}=1; # boy, this is important...

	return $db;
}

sub set_tablenames {
	shift;

	my $postfix = shift;
	croak("No postfix defined?") unless(defined($postfix));

	CertReader::DB::Certificate->meta->table("certificate_$postfix");
	CertReader::DB::CertificateExtension->meta->table("certificate_extension_$postfix");
	CertReader::DB::CertificateValidity->meta->table("certificate_validity_$postfix");
	CertReader::DB::Certificate::CertificateValidityByRootcert->meta->table("certificate_validity_by_rootcert_$postfix");
	CertReader::DB::Certificate::CertificateValidityByRootcert::State->meta->table("certificate_validity_by_rootcert_state_$postfix");
	CertReader::DB::Chain->meta->table("chains_$postfix");
	CertReader::DB::SeenStats->meta->table("seen_stats_$postfix");
	CertReader::DB::VerifyTree->meta->table("verify_tree_$postfix");
	CertReader::DB::RootCerts->meta->table("root_certs_$postfix");
	CertReader::DB::RevokedCerts->meta->table("revoked_certs_$postfix");
	CertReader::DB::CrossSignCandidate->meta->table("cross_sign_candidate_$postfix");
	CertReader::DB::CrossSignCandidateCert->meta->table("csc_cert_$postfix");
	CertReader::DB::CrossSignCandidateMetaData->meta->table("csc_metadata_$postfix");
	CertReader::DB::EvalstateCrossSignCandidate->meta->table("csc_evalstate_$postfix");
	CertReader::DB::CAactor->meta->table("ca_actor_$postfix");
	CertReader::DB::CertificateRelation->meta->table("certificate_relation_$postfix");
	CertReader::DB::CArelation->meta->table("ca_relation_$postfix");
	CertReader::DB::CrtShCertificate->meta->table("crt_sh_certifiate_$postfix");
	CertReader::DB::CrtShRevocationData::MozillaOneCRL->meta->table("crt_sh_mozilla_onecrl_$postfix");
	CertReader::DB::CrtShRevocationData::GoogleRevoked->meta->table("crt_sh_google_revoked_$postfix");
	CertReader::DB::CrtShRevocationData::MicrosoftDisallowed->meta->table("crt_sh_microsoft_disallowedcert_$postfix");
	CertReader::DB::CrtShRevocationData::CRLrevoked->meta->table("crt_sh_crl_revoked_$postfix");
	CertReader::DB::CaChain->meta->table("ca_chain_$postfix");
	CertReader::DB::ValidationStateCertificate->meta->table("validation_state_certificate_$postfix");
	CertReader::DB::ValidationStateRootcert->meta->table("validation_state_rootcert_$postfix");
	CertReader::DB::ValidationStateRootcert::SubstateCert->meta->table("validation_state_rootcert_sub_cert_$postfix");
	CertReader::DB::RootstoreVersion->meta->table("rootstore_version_$postfix");
}

1;
