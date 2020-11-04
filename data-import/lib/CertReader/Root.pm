package CertReader::Root;

use 5.16.1;

use strict;
use warnings;
use Carp;
use Data::Dumper;

use Moose;

use CertReader::DB::CaChain;

has 'rid' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
);

has 'cert' => (
	is => 'rw',
	isa => 'CertReader::DB::Certificate',
	documentation => 'the root certificate',
	required => 1,
);

has 'store' => (
	is => 'rw',
	isa => 'Crypt::OpenSSL::X509::Rootstore',
	required => 1,
);

has 'openssl' => (
	is => 'rw',
	isa => 'Crypt::OpenSSL::X509',
	documentation => 'openssl representation of the root certificate',
	required => 1,
);

has 'chains' => (
	is => 'rw',
	isa => 'HashRef',
	default => sub { {} },
);

sub BUILD {
	my $self = shift;
	my $rootcert_chain = CertReader::CA::Chain->new(
		rid => $self->rid,
		store => $self->store,
		# for the root-cert, we do not need any intermediates. Hence, add an empty list.
		# openssl => [],
		cert_ids => [],
	);
	my $limited_path_analysis = 1;  # TODO Just pretend that we use it; We have no access to this value here
	$self->add_chain_certs($self->cert, $rootcert_chain, $limited_path_analysis)
}

sub set_cache_certs_by_id {
    my ($self, $certs_by_id) = @_;
    $self->{'certs_by_id'} = $certs_by_id;
}

sub get_cache_certs_by_id {
	my ($self) = @_;
	if (defined $self->{'certs_by_id'}) {
		return $self->{'certs_by_id'};
	}
	return undef;
}

sub add_chain_certs {
	my ($self, $cert, $addchain, $limited_path_analysis) = @_;
	my $chain = $self->chains;
	my $subject = $cert->subject;

	if ( $limited_path_analysis ) {
		if ( defined($chain->{$subject}) ) {
			return if ( defined($chain->{$subject}{fingerprints_sha1}{$cert->fingerprint_sha1}) );
		}
		$chain->{$subject}{fingerprints_sha1}{$cert->fingerprint_sha1} = 1;
	}

	# $chain->{$subject}{chains} = [] if (!defined($chain->{$subject}{chains}));
	# push(@{$chain->{$subject}{chains}}, $addchain);
	CertReader::DB::CaChain::Manager->db_add_cachain($addchain, $cert);

}

sub get_chains_count_for_issuer_md5 {
	my ($self, $issuer_md5, $chain_len) = @_;

	return CertReader::DB::CaChain::Manager->get_cachains_count_for_issuer_md5($self->rid, $issuer_md5, $chain_len);
}

# TODO mostly a copy of get_chain_certs
sub get_chains_for_issuer_md5 {
	# WARNING: Loops must be prevented elsewhere
	my ($self, $issuer_md5, $chain_len, $db, $order_by_id_asc) = @_;
	$order_by_id_asc //= 0;

	my $cachains = CertReader::DB::CaChain::Manager->get_cachains_for_issuer_md5($self->rid, $issuer_md5, $chain_len, $db, $order_by_id_asc);

	my $ret = [];
	for my $cachain (@$cachains) {
		# TODO WARNING: Loops must be prevented elsewhere
		# next if $cachain->contains_cert($cert);  # prevent loops

		my $chain = CertReader::CA::Chain->new(
			rid => $cachain->store,
			store => $self->store,
			# openssl => ,
			cert_ids => $cachain->cert_ids,
			ca_chain_id => $cachain->id,
		);
		if (defined $self->{'certs_by_id'}) {
			$chain->set_cache_certs_by_id($self->{'certs_by_id'});
		}
		push(@$ret, $chain);
	}

	return $ret;
}

sub get_chains_cnt_for_cert {
	my ($self, $cert, $chain_len) = @_;

	return CertReader::DB::CaChain::Manager->get_cachains_count_for_cert($self->rid, $cert, $chain_len);
}

sub cert_is_leaf_of_count_cachains {
	my ($self, $cert, $count) = @_;
	return CertReader::DB::CaChain::Manager->cert_is_leaf_of_count_cachains($self->rid, $cert, $count);
}

sub get_chain_certs {
	my ($self, $cert, $chain_len, $order_by_id_asc) = @_;
	$order_by_id_asc //= 0;

	# return undef if( !defined($self->chains->{$cert->issuer}) );

	# my $chains = $self->chains->{$cert->issuer}{chains};
	# my $ret;
	# if (defined($chain_len)) {
	# 	$ret = [];
	# 	for my $chain (@$chains) {
	# 		push(@$ret, $chain) if $chain->length() == $chain_len and !$chain->contains_cert($cert);
	# 	}
	# } else {
	# 	$ret = $chains;
	# }

	my $cachains = CertReader::DB::CaChain::Manager->get_cachains_for_cert($self->rid, $cert, $chain_len, $order_by_id_asc);

	my $ret = [];
	for my $cachain (@$cachains) {
		next if $cachain->contains_cert($cert);  # prevent loops

		my $chain = CertReader::CA::Chain->new(
			rid => $cachain->store,
			store => $self->store,
			# openssl => ,
			cert_ids => $cachain->cert_ids,
			ca_chain_id => $cachain->id,
		);
		if (defined $self->{'certs_by_id'}) {
			$chain->set_cache_certs_by_id($self->{'certs_by_id'});
		}
		push(@$ret, $chain);
	}

	return $ret;
}

sub get_chain_certs_iterator {
	my ($self, $cert, $chain_len, $order_by_id_asc) = @_;

	my $cachain_it = CertReader::DB::CaChain::Manager->get_cachains_iterator_for_cert($self->rid, $cert, $chain_len, $order_by_id_asc);
	my $ret = CertReader::Root::ChainIterator->new (
		cert => $cert,
		root => $self,
		cachain_it => $cachain_it,
	);

	return $ret;
}


package CertReader::Root::ChainIterator;

use 5.16.1;

use strict;
use warnings;
use Carp;

use Moose;

has 'cert' => (
	is => 'rw',
	isa => 'CertReader::DB::Certificate',
	documentation => 'certificate for which the chains have been looked up',
	required => 1,
);

has 'root' => (
	is => 'rw',
	isa => 'CertReader::Root',
	documentation => 'the CertReader::Root of this iterator',
	required => 1,
);

has 'cachain_it' => (
	is => 'rw',
	documentation => 'iterator over ca_chain objects',
	required => 1,
);

sub next {
	my $self = shift;
	my $root = $self->root;

	my $cachain_it = $self->cachain_it;
	while (my $cachain = $cachain_it->next) {
		next if $cachain->contains_cert($self->cert);

		my $chain = CertReader::CA::Chain->new(
			rid => $cachain->store,
			store => $root->store,
			# openssl => ,
			cert_ids => $cachain->cert_ids,
			ca_chain_id => $cachain->id,
		);
		my $cache_certs_by_id = $root->get_cache_certs_by_id;
		if (defined $cache_certs_by_id) {
			$chain->set_cache_certs_by_id($cache_certs_by_id);
		}

		return $chain;
	}

	return undef;
}


1;
