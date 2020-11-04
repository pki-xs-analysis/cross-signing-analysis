package CertReader::OpenSSLVerify;

# factored out logic for the verification with OpenSSL.

use 5.10.1;
use strict;
use warnings;

use Carp;

use Moose::Role;

#requires 'db';
#requires 'ca';

use CertReader::CA::ValidChain;
use Crypt::OpenSSL::X509;
use Digest::MD5 qw/md5_hex/;
use Data::Dumper;
use Date::Parse;
use Date::Format;

use Try::Tiny;

=blob only used in NSS verifications. Probably not needed anymore

# validate and only use the provided chain.
sub validateOnlyChain {
	my ($self, $chainref, $rootcerts, $ts) = @_;

	my @servercerts = @$chainref;

	# $ts //= time;
	croak("validateChain: undefined timestamp") if !defined($ts);

	my $leafcert;
	my @dercerts;

	my $certcache = $self->certcache;

	# please factor out getcerts at some point of time
	# first - try to locate all needed certificates...
	while ( my $cert = shift @servercerts ) {

		my $b = str2time($cert->not_before);
		my $a = str2time($cert->not_after);

		croak("certificate missing") unless ((defined($a) && defined($b)));

		unless ( defined($leafcert) ) {
			# this is the leaf certificate
			#
			# assume the first cert is never superfluous and contains the host certificate
			# curse everyone if someone also gets that wrong.
			#

			$leafcert = $cert->openssl;

		} else {
			push (@dercerts, $cert->openssl);
		}
	}

	return $rootcerts->verify($leafcert, \@dercerts, Crypt::OpenSSL::X509::X509_PURPOSE_ANY ,$ts);
}

=cut

sub epoch2str {
	my $epoch = shift;
	return time2str("%Y-%m-%d %H:%M:%S", $epoch, "UTC");
}

sub valid_chain_is_provided_chain {
	# valid_chain: must be the chain returned by $chain->store->verify_chain
	# $provided_chain: must be the chain of openssl certs provided to $chain->store->verify_chain
	#                  Be sure that it the provided chain does not contain the rootcert or the leafcert (see below)
	my ($valid_chain, $provided_chain) = @_;

	# We are only interested in results that use the full provided chain.
	my $len_provided_chain = scalar @$provided_chain;
	my $len_valid_chain = scalar @$valid_chain;
	if ($len_valid_chain == $len_provided_chain + 2) { # valid_chain contains rootcert and leafcert, provided_chain does not
		return 1;
	}

	return 0;

	# TODO Skipping shorter chains is fine, but does openssl hide valid
	# paths with the desired length from us such that we miss them?
}

sub validateChain {
	my ($self, $cert, $ts, $worker_prefix, $write_to_db, $chain_len, $cert_validation_state) = @_;
	my $watchdog_timeout_seconds = 600;
	my $watchdog_timeout = time + $watchdog_timeout_seconds;
	my $watchdog_function_start = time;
	# $ts //= time;
	$worker_prefix = "" if !defined($worker_prefix);
	croak("$worker_prefix validateChain: undefined timestamp") if !defined($ts);

	my $try_any_day = 0;
	if ($self->attime_try_any_day) {
		$try_any_day = 1;
		$ts = str2time($cert->not_before, "GMT") + 1
	}

	my $b_local = str2time($cert->not_before, "GMT");
	my $a_local = str2time($cert->not_after, "GMT");

	if ( $ts > $a_local || $ts < $b_local ) {
		#say STDERR "Invalid date for leaf cert";
		return (defined(wantarray) && wantarray) ? () : 0;
	}

	# # my $possiblechains = $self->chains->{$cert->issuer};
	# my $possiblechains = [];
	# for my $rid ( keys %{$self->ca} ) {
	# 	my $r = $self->ca->{$rid};
	# 	my $r_possible_chains = $r->get_chain_certs($cert);
	# 	push(@$possiblechains, @$r_possible_chains);
	# }
	# return (defined(wantarray) && wantarray) ? () : 0 if ( !defined($possiblechains) ); # no subject match :(

	my %results;

	my $osslcert;
	my $success = try {
		$osslcert = $cert->openssl;
		1;
	} catch {
		warn "$worker_prefix Could not parse certificate ".$cert->id." in validateChain: $_. Returning it as being non valid...";
		return 0;
	};
	return %results unless $success;

	my $chain_cnt_total = 0;
	my $rid_cnt = scalar keys %{$self->ca};
	# Be sure to keep this sort ascending
	for my $rid ( sort {$a <=> $b} keys %{$self->ca} ) {
		if (defined $cert_validation_state) {
			if (defined $cert_validation_state->partial_state_rid) {
				if ($rid <= $cert_validation_state->partial_state_rid) {
					say "$worker_prefix Skipping rid $rid for cert $cert->{id}";
					next;
				}
			}
		}

		my $chain_cnt_rid = 0;
		my $chain_cnt_rid_including_skipped = 0;
		my $r = $self->ca->{$rid};
		my $order_by_id_asc = 1;  # very important for tracking the partial validation state
		my $r_possiblechains_it = $r->get_chain_certs_iterator($cert, $chain_len, $order_by_id_asc);

	# TODO wrong indentation
	# for my $chain (@$possiblechains) {
	my $cachain_skipping_in_progress = 0;
	my $cachains_skipped_cnt = 0;
	while (my $chain = $r_possiblechains_it->next) {
		$chain_cnt_rid_including_skipped += 1;
		if (defined $cert_validation_state) {
			if (defined $cert_validation_state->partial_state_cachain) {
				if ($chain->ca_chain_id <= $cert_validation_state->partial_state_cachain) {
					unless ($cachain_skipping_in_progress) {
						my $cachain_id_already_processed_max = $cert_validation_state->partial_state_cachain;
						say "$worker_prefix Skipping ca_chains with ca_chain id <= $cachain_id_already_processed_max (rid $rid, cert $cert->{id})";
						$cachain_skipping_in_progress = 1;
					}
					$cachains_skipped_cnt += 1;
					next;
				} else {
					if ($cachain_skipping_in_progress) {
						my $cachain_id_already_processed_max = $cert_validation_state->partial_state_cachain;
						say "$worker_prefix \tSkipping ca_chains finished: Skipped $cachains_skipped_cnt ca_chains with id <= $cachain_id_already_processed_max (rid $rid, cert $cert->{id})";
						$cachain_skipping_in_progress = 0;
					}
				}
			}
		}

		$chain_cnt_total += 1;
		$chain_cnt_rid += 1;
		if ($chain_cnt_total % 100000 == 0){
			my $cur_time = time;
			if ($cur_time > $watchdog_timeout) {
				my $running_for_seconds = $cur_time - $watchdog_function_start;
				say "$worker_prefix    WATCHDOG " . __FILE__ . ":". __LINE__ . "  cert $cert->{id}, chains_total $chain_cnt_total, root $rid/$rid_cnt, chain_cnt_rid $chain_cnt_rid (incl. skipped: $chain_cnt_rid_including_skipped), running $running_for_seconds sec";
				$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
			}
		}

		if ($chain->contains_cert($cert)) {
			# We do not want loops --> nothing to do for this chain; Keep track of state before proceeding with next
			# TODO: Duplicates code from below. Refactor by getting rid of 'next' in favor of a proper large if block
			if ($write_to_db) {
				if (defined $cert_validation_state) {
					if ($chain_cnt_total % 100000 == 0){
						# occasionally keep track of state
						$cert_validation_state->partial_state_cachain($chain->ca_chain_id);
						$cert_validation_state->save;
					}
				}
			}

			next;  # prevent loops
		}

		my $chain_rootcert = $self->ca->{$chain->rid}->cert;
		my $ts_not_before = undef;
		my $ts_not_after = undef;
		if ($try_any_day) {
			my ($not_before_max, $not_after_min) = get_validity_period($cert, $chain, $chain_rootcert);
			if ($not_before_max > $not_after_min) {
				# Give openssl a chance even if $not_after_min < $not_before_max
				# next;
			}
			$ts_not_before = $not_before_max;
			$ts_not_after = $not_after_min;
		} else {
			croak("$worker_prefix ERROR: Validation for a specific date no longer supported.");
		}
		# Here the actual detection of a valid chain happens
		# Assumptions are:
		# * $chain->store contains exactly one root certificate
		# * $chain->chain contains the intermediates that may build up the chain from $osslcert up to the aforementioned root certificate
		#   (if no such path can be built, the verification will be unsuccessful and $res will be undefined). This chain is a path, i.e.,
		#   directed, acyclic and cert has exactly one parent and one child (shortcuts accross this path may happen, but the shortcuts must not
		#   introduce new certificates that are not part of the path otherwise, i.e., the root may, e.g., have signed two intermediate certificates
		#   of the path).
		#
		# These preconditions ensure that only one path will be checked by verify_chain. This requires multiple calls to verify_chain for
		# each possible chain, but also prevents that we only detect one valid path if multiple chains make up multiple valid paths.
		# Note that, with a single chain, still there may be multiple paths if there is a shortcut, e.g., the root cert signed two of the
		# certificates that are in the chain. However, (as of now) verify_chain falls back to openssl's X509_verify_cert which, according to
		# 'man 1 verify' first tries to find a parent in the untrusted certificates, i.e., the $chain->chain, before looking for a parent in
		# the trusted certificates, i.e., the root certificate stored in $chain->store [1]. Hence, the validation should build the longest possible
		# path instead of choosing shortcuts. The shorter paths (using shortcuts) will be added when the chain that represents this shortcut
		# gets passed to verify_chain.
		#
		# [1] This is implemented in crypto/x509/x509_vfy.c:build_chain. If X509_V_FLAG_TRUSTED_FIRST is not set, it loops over the supplied untrusted
		# certificates. Only when these do not contain a matching issuer certificates, it starts to search the trusted certificates.
		my $chain_openssl = $chain->openssl;
		my $res_not_before = $chain->store->verify_chain($osslcert, $chain_openssl, Crypt::OpenSSL::X509::X509_PURPOSE_ANY, $ts_not_before);
		# RFC: The validity period for a certificate is the period of time from notBefore through notAfter, inclusive.
		# OpenSSL: excludes NotAfter (but cert is valid one second before)
		my $ts_not_after_satisfy_openssl = $ts_not_after - 1;
		my $res_not_after = $chain->store->verify_chain($osslcert, $chain_openssl, Crypt::OpenSSL::X509::X509_PURPOSE_ANY, $ts_not_after_satisfy_openssl);

		my $chain_not_before = undef;
		my $chain_not_after = undef;
		if (defined($res_not_before)) {
			# We are only interested in results that use the full provided chain.
			if (valid_chain_is_provided_chain($res_not_before, $chain_openssl)) {
				$chain_not_before = epoch2str($ts_not_before);
			} else {
				undef $res_not_before;
			}
		}
		if (defined($res_not_after)) {
			# We are only interested in results that use the full provided chain.
			if (valid_chain_is_provided_chain($res_not_after, $chain_openssl)) {
				$chain_not_after = epoch2str($ts_not_after);
			} else {
				undef $res_not_after;
				if (defined $res_not_before) {
					my $ts_failed = epoch2str($ts_not_after);
					warn "valid at not_before ($chain_not_before), but failed for not_after ($ts_failed)";
				}
			}
		}


		my $res = $res_not_before;  # TODO assumes that $res_not_before and $res_not_after represent the same chain
		if ( defined($res) ) {

			my $certs_by_certhash = {};
			$certs_by_certhash->{$cert->cert_hash} = $cert;
			$certs_by_certhash->{$chain_rootcert->cert_hash} = $chain_rootcert;
			for my $chaincert (@{$chain->certs}) {
				$certs_by_certhash->{$chaincert->cert_hash} = $chaincert;
			}

			my @validchain_certs;
			for my $res_cert_ossl (@$res) {
				my $res_cert_certhash = md5_hex($res_cert_ossl->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1));
				my $res_cert = $certs_by_certhash->{$res_cert_certhash};
				push(@validchain_certs, $res_cert);
			}

			my $validchain = CertReader::CA::ValidChain->new(
				openssl => $res,
				certs => \@validchain_certs,
				not_before => $chain_not_before,
				not_after => $chain_not_after,
				ca_chain_id => $chain->ca_chain_id,
			);

			if ($write_to_db) {
				$self->savetree($cert, $chain->rid, $validchain, undef, $self->attime);
			} else {
				$results{$chain->rid} //= [];
				push(@{$results{$chain->rid}}, $validchain);
			}
		}

		# ca_chain finished
		if ($write_to_db) {
			if (defined $cert_validation_state) {
				if ($chain_cnt_total % 100000 == 0){
					# occasionally keep track of state
					# WARNING: Duplicated code above; before 'next' to prevent loops
					$cert_validation_state->partial_state_cachain($chain->ca_chain_id);
					$cert_validation_state->save;
				}
			}
		}

	}  # end of 'while (my $chain = $r_possiblechains_it->next) {'

	# rid finished
	if ($write_to_db) {
		if (defined $cert_validation_state) {
			$cert_validation_state->partial_state_rid($rid);
			$cert_validation_state->partial_state_cachain(undef);
			$cert_validation_state->save;
		}
	}

	}  # for my $rid ...

	if ($write_to_db) {
		return;
	} else {
		return %results;
	}
}

# validate against a single store
# leafcert -> cert to validate
# rid -> id of root store to use
sub validateChainSingle {
	my ($self, $leafcert, $rid, $ts, $chain_len, $worker_prefix, $possiblechains_cnt, $write_to_db, $watchdog_state_str, $cert_validationstatus_in_rid) = @_;
	$write_to_db //= 0;
	$watchdog_state_str //= "";
	my $found_valid_chain = 0;
	my $watchdog_timeout_seconds = 300;
	my $watchdog_timeout = time + $watchdog_timeout_seconds;
#	my $certcache = $self->certcache;
	# $ts //= time;
	$worker_prefix = "" if !defined($worker_prefix);
	croak("$worker_prefix validateChainSingle: undefined timestamp") if !defined($ts);
	my $r = $self->ca->{$rid};
	my $store = $r->store;
	croak("$worker_prefix invalid rid") unless defined($r);

	my $try_any_day = 0;
	if ($self->attime_try_any_day) {
		$try_any_day = 1;
		$ts = str2time($leafcert->not_before, "GMT") + 1
	}

	{
		my $cert = $leafcert;
		my $b_local = str2time($cert->not_before, "GMT");
		my $a_local = str2time($cert->not_after, "GMT");

		if ( $ts > $a_local || $ts < $b_local ) {
			#say STDERR "Invalid date for leaf cert";
			return (defined(wantarray) && wantarray) ? () : 0;
		}
	}

	my $order_by_id_asc = 1;  # very important for tracking the partial validation state
	my $intermediatechains_it = $r->get_chain_certs_iterator($leafcert, $chain_len, $order_by_id_asc);

	my @chains;
	my $chain_cnt = 0;
	my $chain_cnt_total = (defined $possiblechains_cnt) ? $possiblechains_cnt : $r->get_chains_cnt_for_cert($leafcert, $chain_len);
	my $time_chains_processing_started = time;
	my $cachain_skipping_in_progress = 0;
	my $cachains_skipped_cnt = 0;
	CHAINS: while (my $intermediates = $intermediatechains_it->next) {
		if (defined $cert_validationstatus_in_rid) {
			if (defined $cert_validationstatus_in_rid->partial_state_cachain) {
				my $partial_state_cachain_is_for_current_chainlen = 0;  # we may not be updating the tracking status; Make sure to not skip unchecked cachains
				if (defined $cert_validationstatus_in_rid->partial_state_chainlen) {
					$partial_state_cachain_is_for_current_chainlen = 1 if ($cert_validationstatus_in_rid->partial_state_chainlen + 1 == $chain_len);
				} else {
					$partial_state_cachain_is_for_current_chainlen = 1 if ($chain_len == 0);
				}
				if ($partial_state_cachain_is_for_current_chainlen){
					if ($intermediates->ca_chain_id <= $cert_validationstatus_in_rid->partial_state_cachain) {
						unless ($cachain_skipping_in_progress) {
							my $cachain_id_already_processed_max = $cert_validationstatus_in_rid->partial_state_cachain;
							say "$worker_prefix Skipping ca_chains with ca_chain id <= $cachain_id_already_processed_max (rid $rid, cert $leafcert->{id})";
							$cachain_skipping_in_progress = 1;

							# We will skip already checked chains. Retrieve if at least one of the skipped ca_chains was valid
							if (defined $cert_validationstatus_in_rid->partial_state_found_valid_chain) {
								if ($cert_validationstatus_in_rid->partial_state_found_valid_chain) {
									$found_valid_chain = $cert_validationstatus_in_rid->partial_state_found_valid_chain;
								}
							}
						}
						$cachains_skipped_cnt += 1;
						next;
					} else {
						if ($cachain_skipping_in_progress) {
							my $cachain_id_already_processed_max = $cert_validationstatus_in_rid->partial_state_cachain;
							say "$worker_prefix \tSkipping ca_chains finished: Skipped $cachains_skipped_cnt ca_chains with id <= $cachain_id_already_processed_max (rid $rid, cert $leafcert->{id})";
							$cachain_skipping_in_progress = 0;
						}
					}
				}
			}
		}
		$chain_cnt += 1;

		if ($intermediates->contains_cert($leafcert)) {
			# We do not want loops --> nothing to do for this chain; Keep track of state before proceeding with next
			# TODO: Duplicates code from below. Refactor by getting rid of 'next' in favor of a proper large if block
			if ($write_to_db) {
				if (defined $cert_validationstatus_in_rid and $self->track_cachain_state) {
					if ($chain_cnt % 100000 == 0){
						# occasionally keep track of state
						$cert_validationstatus_in_rid->partial_state_cachain($intermediates->ca_chain_id);
						$cert_validationstatus_in_rid->partial_state_found_valid_chain($found_valid_chain);
						$cert_validationstatus_in_rid->save;
					}
				}
			}

			next;  # prevent loops
		}

		# say "testing rid $rid, cert " . $leafcert->id . " chain " . $intermediates->get_path; # TODO debug remove
		if ($try_any_day) {
			my ($not_before_max, $not_after_min) = get_validity_period($leafcert, $intermediates, $r->cert);
			if ($not_before_max > $not_after_min) {
				# Give openssl a chance even if $not_after_min < $not_before_max
				# next;
			}
			$ts = $not_before_max; # test at beginning of validity, could also select any other
		}

		#say "Namematch for ".$leafcert->subject." and ".$r->cert->subject;
		my $intermediates_openssl = $intermediates->openssl;
		my $res = $store->verify_chain($leafcert->openssl, $intermediates_openssl, Crypt::OpenSSL::X509::X509_PURPOSE_ANY, $ts);

		if (defined($res)) {
			if (valid_chain_is_provided_chain($res, $intermediates_openssl)) {
				;
			} else {
				undef $res;
			}
		}

		if ( defined($res) ) {
			# we have verified
			unless ($write_to_db) {
				return 1 unless ( defined wantarray && wantarray ); # this is the normal case - return 1.
			}

			# return @$res;
			my @ccert_ids;
			# Build ccerts as DB object counterpart of $res which stores certs in openssl format
			# TODO next line would be absolutely correct, but requires database access. Rather use a global map
			# @ccerts = $self->getcerts( map { md5_hex($_->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1)) } @$res );
			push @ccert_ids, $leafcert->id;
			push @ccert_ids, @{$intermediates->cert_ids};
			push @ccert_ids, $r->cert->id;
			my $chain = CertReader::CA::Chain->new(
				rid => $rid,
				store => $store,
				# openssl => $res,
				cert_ids => \@ccert_ids,
			);

			$found_valid_chain = 1;
			if ($write_to_db) {
				# remove last - is rootcert;
				# pop @{$chain->openssl};
				pop @{$chain->cert_ids};

				$r->add_chain_certs($leafcert, $chain, $self->limited_path_analysis);
				# print "$prefix rootstore $rid - adding chain for cert_id " . $cert->id . "("; for my $c (@{$chain->certs}) {print $c->id . ".";} say ")"; # DEBUG
			} else {
				push(@chains, $chain);
			}
		}

		# ca_chain finished
		if ($write_to_db) {
			if (defined $cert_validationstatus_in_rid and $self->track_cachain_state) {
				if ($chain_cnt % 100000 == 0){
					# occasionally keep track of state
					# WARNING: Duplicated code above; before 'next' to prevent loops
					$cert_validationstatus_in_rid->partial_state_cachain($intermediates->ca_chain_id);
					$cert_validationstatus_in_rid->partial_state_found_valid_chain($found_valid_chain);
					$cert_validationstatus_in_rid->save;
				}
			}
		}

		my $cur_time = time;
		if ($cur_time > $watchdog_timeout) {
			my $avg_time_per_chain = ($chain_cnt != 0) ? ($cur_time - $time_chains_processing_started) / $chain_cnt : "n/a";
			say "$worker_prefix    WATCHDOG " . __FILE__ . ":". __LINE__ . "$watchdog_state_str, cert $leafcert->{id}, chain $chain_cnt/$chain_cnt_total, ~ $avg_time_per_chain s/chain";
			$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
		}
		# say "$worker_prefix     WATCHDOG already checked $chain_cnt possible chains for cert " . $leafcert->id . " (rootstore $rid, chainlen $chain_len)" if ($chain_cnt % 10000 == 0);
	}

	if ($write_to_db) {
		return $found_valid_chain;
	}

	if (scalar @chains > 0) {
		return @chains;
	}

	return 0 unless ( defined wantarray && wantarray );
	return ();
}

sub get_validity_period {
	my ($leafcert, $chain, $rootcert) = @_;

	# calculate overlapping validity period
	my $not_before_max = str2time($leafcert->not_before, "GMT");
	my $not_after_min = str2time($leafcert->not_after, "GMT");

	if ($chain->length > 0) {
		my ($chain_not_before, $chain_not_after) = $chain->get_validity_period;
		$not_before_max = $chain_not_before if $not_before_max < $chain_not_before;
		$not_after_min = $chain_not_after if $chain_not_after < $not_after_min;
	}

	# not sure if openssl checks the validity time of the root certs, hence only consider it if
	# it does not result in an empty validity period otherwise just let openssl decide during validation
	my $root_not_before = str2time($rootcert->not_before, "GMT");
	my $root_not_after = str2time($rootcert->not_after, "GMT");
	if ($root_not_before < $root_not_after) {
		if ($not_before_max < $root_not_before) {
			if ($root_not_before < $not_after_min) { # prevent empty validity period due to rootcert
				$not_before_max = $root_not_before;
			}
		}
		if ($not_after_min > $root_not_after) {
			if ($not_before_max < $root_not_after) { # prevent empty validity period due to rootcert
				$not_after_min = $root_not_after;
			}
		}
	}

	return $not_before_max, $not_after_min;
}

1;
