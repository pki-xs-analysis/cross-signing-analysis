package CertReader::CA;

use 5.16.1;

use forks; # ALWAYS LOAD AS FIRST MODULE, if possible
# Tell Forks::Queue to not play signal bomb
# Alternatively to disabling signals for queue signaling is to ensure a sufficiently
# Large stepsize such that not too many elements are withdrawn from the queue while
# a thread blocks, e.g., while waiting for response of the database. However, calculating
# an appropriate stepsize is quite system and situation dependent.
BEGIN { $ENV{FORKS_QUEUE_NOTIFY} = 0; } # Tell Forks::Queue to not play signal bomb
use Forks::Queue;

use strict;
use warnings;
use utf8;
use Carp;

use Crypt::OpenSSL::X509;
use Data::Dumper;
use Date::Format;
use Date::Parse;

# JSON::MaybeXS uses Cpanel::JSON::XS if installed, otherwise Pure-Perl version
# https://perlmaven.com/json
# use JSON::MaybeXS qw(encode_json decode_json);

use Moose::Role;
with 'CertReader::ORM';
with 'CertReader::OpenSSLVerify';

use CertReader::Root;
use CertReader::CA::Chain;

# Command-line options

has 'track_cachain_state' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 1,
	documentation => 'Keep track of ca_chain generation state. Default: True',
);

has 'skip_certs_with_count_valid_cachains_for_rootcert' => (
	is => 'rw',
	isa => 'Int',
	required => 0,
	default => 0,
	documentation => "When creating ca_chains, skip those certs that already have X valid ca_chains that root in the rootcert in question. Implies track_cachain_state = FALSE",
);


# Attributes

has '_ca' => (
	accessor => 'ca',
	is => 'rw',
	documentation => 'Hash of all one-cert root-stores...',
#	lazy => 1,
#	builder => '_build_ca',
);

has '_chains' => (
	accessor => 'chains',
	is => 'rw',
	isa => 'HashRef',
	default => sub { {} },
);

has '_thorough' => (
	accessor => 'thorough',
	is => 'rw',
	isa => 'Bool',
	default => 0,
	documentation => 'check certificates thorougly? It no, trust db when loading',
);

sub _build_ca {
	my $self = shift;

	$self->populate_cas;
}

sub populate_cas {
	my $self = shift;

	$self->populate_roots;
	# Now that the roots are loaded - try to resolve intermediates...
	$self->populate_intermediates;
	# $self->populate_quicksearch;
	say "Done populating...";
}

sub populate_quicksearch {
	my $self = shift;
	# this one is pretty nifty and easy. Just create a global subject list of subjects for all
	# the stores and point back to the respective store :)

	for my $rid ( keys %{$self->ca} ) {
		my $r = $self->ca->{$rid};
		for my $subject ( keys %{$r->chains} ) {
			my $chains = $r->chains->{$subject}{chains};
			for my $chain ( @$chains ) {
				$self->chains->{$subject} //= [];
				push(@{$self->chains->{$subject}}, $chain);
			}
		}
	}
}

sub populate_roots {
	my $self = shift;
	my $r = {};

	my $roots = CertReader::DB::RootCerts::Manager->get_rootcerts(db => $self->db);
	for my $root ( @$roots ) {
		my $id = $root->id;
		my $osslcert = $root->cert->openssl;
		my $store = Crypt::OpenSSL::X509::Rootstore->new();
		$store->add_cert($osslcert);
		my $rc = CertReader::Root->new (
			rid => $id,
			cert => $root->cert,
			openssl => $osslcert,
			store => $store,
		);
		$r->{$id} = $rc;
	}

	$self->ca($r);
}

sub populate_intermediates {
	my ($self, $ts) = @_;
	my $use_cacert_cache = 1;  # TODO make this an cmd-option  # TODO even when setting this to 0, the workers get all cacerts via $certificates, i.e., cacerts are kept in RAM

	if ($self->skip_certs_with_count_valid_cachains_for_rootcert > 0) {
		$self->track_cachain_state(0);
	}

	# $ts //= time;
	# croak("Undefined ts") if !defined($ts);
	$ts = $self->attime;
	my $attime_dt = DateTime->from_epoch( epoch => $self->attime);

	my $sql = "SELECT * FROM certificate_$self->{tablepostfix} WHERE selfsigned='F' AND ca='T'";
	if ($self->ignore_google_ct_precert_signing_certs) {
		$sql .= " and not (subject like '%Google Certificate Transparency (Precert Signing)%')";
	}
	$sql .= " order by id desc";
	my $certificates = CertReader::DB::Certificate::Manager->get_objects_from_sql ( db => $self->db,
		# TODO speed up by only considering certificates that are valid at the current $self->attime
		sql => $sql,
	);

	my $certs_by_id;
	if ($use_cacert_cache) {
		$certs_by_id = {};
		for my $cert (@$certificates) {
			$certs_by_id->{$cert->id} = $cert;
			$cert->openssl; # We will need the openssl represtantion, so create it know (s.t. it is available in caches)
		}
		for my $rid (keys %{$self->ca}) {
			my $cert = $self->ca->{$rid}->cert;
			$certs_by_id->{$self->ca->{$rid}->cert->id} = $cert;
			$cert->openssl; # We will need the openssl represtantion, so create it know (s.t. it is available in caches)
		}

		# Use the cache for operations of roots
		for my $rid (keys %{$self->ca}) {
			$self->ca->{$rid}->set_cache_certs_by_id($certs_by_id);
		}
	}

	if (defined $self->skip_cachain_generation) {
		if ($self->skip_cachain_generation) {
			return;
		}
	}

	my $certificates_by_md5_issuer = {};
	for my $cert (@$certificates) {
		my $issuer_md5 = CertReader::DB::CaChain::Manager->_cert_issuer_md5($cert);
		$certificates_by_md5_issuer->{$issuer_md5} //= [];
		push(@{$certificates_by_md5_issuer->{$issuer_md5}}, $cert);
	}

	my $rootstore_queue = Forks::Queue->new( impl => 'Shmem' );

	for my $rid ( sort {$b <=> $a} keys %{$self->ca} ) {
		$rootstore_queue->enqueue($rid);
	}
	$rootstore_queue->end();

	# See comment before '$results_queue->enqueue($res);' at the end of
	# populate_intermediates_worker() for an explanation, why we use a queue
	# to retrieve the data from the clients instead of using return.
	my @results_queues;

	CertReader::App::VerifyCerts->disconnect_db_handlers($self);

	my @worker_main;
	for ( 1 .. $self->nworker ) {
		my $results_queue = Forks::Queue->new( impl => 'Shmem' );
		push(@results_queues, $results_queue);
		my $thr = threads->create( \&populate_intermediates_worker, $self, $certificates, $certificates_by_md5_issuer, $rootstore_queue, $results_queue );
		push(@worker_main, $thr);
	}

	CertReader::App::VerifyCerts->reconnect_db_handlers($self);

	say "Waiting for worker to finish their work ...";
	my $watchdog_timeout_seconds = 600;
	my $watchdog_timeout = time + $watchdog_timeout_seconds;
	while(scalar threads->list(threads::running)) {
		select(undef, undef, undef, 10);

		my $cur_time = time;
		if ($cur_time > $watchdog_timeout) {
			my @worker_main_running;
			my @worker_main_joinable;
			for my $thr (@worker_main) {
				push(@worker_main_running, $thr) if $thr->is_running;
				push(@worker_main_joinable, $thr) if $thr->is_joinable;
			}
			my $running_worker_main_cnt = scalar @worker_main_running;
			my $running_worker_main_str = join(' ', map {$_->tid} @worker_main_running);
			my $joinable_worker_main_cnt = scalar @worker_main_joinable;
			my $joinable_worker_main_str = join(' ', map {$_->tid} @worker_main_joinable);

			my $running_threads_cnt = scalar threads->list(threads::running);
			my $str_running_threads = join(' ', map {$_->tid} threads->list(threads::running));
			my $joinable_threads_cnt = scalar threads->list(threads::joinable);
			my $str_joinable_threads = join(' ', map {$_->tid} threads->list(threads::joinable));

			my $watchdog_str = "MAIN THREAD";
			$watchdog_str .= "\n\tMain threads: running threads: $running_worker_main_cnt ($running_worker_main_str), joinable threads: $joinable_worker_main_cnt ($joinable_worker_main_str)";
			$watchdog_str .= "\n\tAll threads : running threads: $running_threads_cnt ($str_running_threads), joinable threads: $joinable_threads_cnt ($str_joinable_threads)";
			say $watchdog_str;
			$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
		}
	}
	foreach my $thr ( threads->list() ) {
		$thr->join();
		if (my $err = $thr->error()) {
			croak("MAIN THREAD: ERROR in populate_intermediates_worker: $err\n");
		}
	}
	say "All worker finished";

	say "Importing stuff from results_queues ...";
	for my $q (@results_queues) {
		$q->end(); # All workers are done. So this is safe.
		while (my $w_res = $q->dequeue()) {
			$self->populate_intermediates_import($w_res);
		}
	}
}

sub populate_intermediates_worker {

	my ($self, $certificates, $certificates_by_md5_issuer, $rootstore_queue, $results_queue) = @_;

	my $prefix = "Worker " . threads->self()->tid() . ":";
	say "$prefix started.";

	CertReader::App::VerifyCerts->reconnect_db_handlers($self);

	if ($self->nsubworker > 1) {
		# wait a few seconds until other workers started.
		# Purely cosmentic: We want the subworkers have higher thread ids
		select(undef, undef, undef, 5);
	}

	# we have to have looping somewhere in our verification code. Let's do it here, where we can do it one time and be
	# done with it for good.
	#
	# So - we will walk through all our certificates (for each store) in turns. Validate all against the current state.
	# After done (with all), add one "layer" of sub-ca-certs. Repeat.
	#
	# God, this will probably give us many validation paths because of all the different intermediate-certificates we see :(
	my @handled_rids;
	while ( my $rid = $rootstore_queue->dequeue() ) {
		say "$prefix Populating intermediates for rootstore $rid";
		my $watchdog_rid_starttime = time;
		my $watchdog_timeout_seconds = 300;
		my $watchdog_timeout = time + $watchdog_timeout_seconds;
		push(@handled_rids, $rid);
		my $croot = $self->ca->{$rid};
		my %fp; # sha1 fingerprints that we already know.
		if ($self->limited_path_analysis) {
			$fp{$croot->cert->fingerprint_sha1} = 1;
		}

		# TODO
		# Here would be the time to check if we have a CertReader::DB::ValidationStateRootcert::SubstateCert
		# in the DB for each CA certificate in $certificates
		# If we lack a validation state for a cert, this has not yet been validated against any existing ca_chain,
		# so we should start this and from then on, validate all certs in $certificates against any ca_chain that
		# has been created later than their CertReader::DB::ValidationStateRootcert::SubstateCert->verified_at
		#
		# UPDATE: Actually not true: We skip certs which do not have a potential path; These will not have an DB entry
		# 		We need to change this or use another check if a new certificate was added

		my $rid_validationstate = CertReader::DB::ValidationStateRootcert->new(rootcert_id => $rid);
		if ( $rid_validationstate->load(speculative => 1) ) {
			;
		} else {
			# We do not know a validation state, let's start a new state
			$rid_validationstate->partial_state_started_at(time2str("%Y-%m-%d %H:%M:%S", time, "UTC"));
			$rid_validationstate->partial_state_chainlen(-1);
			$rid_validationstate->save;
		}

		if (defined($rid_validationstate->verified_at)) {
			# TODO check for conditions that require re-evaluation
			say "$prefix Skipping rid $rid: Already fully validated. Only safe if no new ca certs were added!";
			next;
		}

		my $chain_len = $rid_validationstate->partial_state_chainlen;
LOOP:
		$chain_len += 1; # In each round, skip chains with smaller lengths as we already checked them
		my $stable = 1; # did we add any new certificates in this round?
		my @validcerts = ();
		my $validcerts_cnt = 0;
		my $time_chain_len_started = time;
		my $certs_offloaded_to_workers = 0;

		say "$prefix WARNING large chain_len: $chain_len (rootstore $rid)" if ($chain_len > 1 and $chain_len % 100 == 0);

		my $intermediates_subworker_queue;
		my @intermediates_subworker_threads;
		if ($self->nsubworker > 1) {
			$intermediates_subworker_queue = Forks::Queue->new( impl => 'Shmem' );
			CertReader::App::VerifyCerts->disconnect_db_handlers($self);
			for my $subworker_id ( 1 .. $self->nsubworker ) {
				my $common_prefix = "Worker " . threads->self()->tid() . ".$subworker_id";
				my $thr = threads->create( {'context' => 'scalar'}, \&populate_intermediates_subworker, $self, $common_prefix, $rid, $chain_len, $rid_validationstate, $intermediates_subworker_queue );
				push(@intermediates_subworker_threads, $thr);
			}
			CertReader::App::VerifyCerts->reconnect_db_handlers($self);
		}

		my $issuer_md5_cnt = 0;
		my $issuer_md5_cnt_total = scalar (keys %$certificates_by_md5_issuer);

		for my $issuer_md5 (sort keys %$certificates_by_md5_issuer) {
			$issuer_md5_cnt += 1;

			my $cur_time = time;
			if ($cur_time > $watchdog_timeout) {
				my $avg_sec_per_md5 = $issuer_md5_cnt > 1 ? ($cur_time - $watchdog_rid_starttime) / ($issuer_md5_cnt - 1) : "n/a";
				my $watchdog_str = "";
				$watchdog_str .= "$prefix    WATCHDOG " . __FILE__ . ":". __LINE__;
				$watchdog_str .= "  root $rid";
				$watchdog_str .= ", chain_len $chain_len";
				$watchdog_str .= ", md5 $issuer_md5_cnt/$issuer_md5_cnt_total";
				$watchdog_str .= ", on avg $avg_sec_per_md5 sec/md5";
				say $watchdog_str;
				$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
			}

			my $possiblechains_cnt = $croot->get_chains_count_for_issuer_md5($issuer_md5, $chain_len);
			if ($possiblechains_cnt == 0) {
				next;
			}

			my $cert_cnt = 0;
			my $cert_cnt_total = scalar @{$certificates_by_md5_issuer->{$issuer_md5}};
			my $watchdog_certs_for_md5_timeout = time + $watchdog_timeout_seconds;
			my $watchdog_certs_for_md5_starttime = time;
			# for my $cert (@$certificates) {
			for my $cert (sort {$a->id <=> $b->id} @{$certificates_by_md5_issuer->{$issuer_md5}}) {
				$cert_cnt += 1;

				if ($self->limited_path_analysis) {
					next if defined($fp{$cert->fingerprint_sha1});
				}

				if ($self->nsubworker > 1) {

					# offload validation to subworker
					$intermediates_subworker_queue->enqueue($cert->id);
					$certs_offloaded_to_workers += 1;

				} else {
					my $watchdog_state_str = "";
					$watchdog_state_str .= "  root $rid";
					$watchdog_state_str .= ", chain_len $chain_len";
					$watchdog_state_str .= ", md5 $issuer_md5_cnt/$issuer_md5_cnt_total";
					$watchdog_state_str .= ", cert $cert_cnt/$cert_cnt_total";
					my $found_valid_chain = $self->_validate_cert($rid, $cert, $chain_len, $possiblechains_cnt, $prefix, $watchdog_state_str, $rid_validationstate);
					unless (defined $found_valid_chain) {
						next;
					}
					if ($found_valid_chain) {
						$validcerts_cnt += 1;
						$stable = 0;

						if ($self->limited_path_analysis) {
							$fp{$cert->fingerprint_sha1} = 1;
						}
					}

					$cur_time = time;
					if ($cur_time > $watchdog_certs_for_md5_timeout) {
						my $avg_sec_per_md5 = $issuer_md5_cnt > 1 ? ($cur_time - $watchdog_rid_starttime) / ($issuer_md5_cnt - 1) : "n/a";
						my $avg_sec_per_cert = ($cur_time - $watchdog_certs_for_md5_starttime) / $cert_cnt;
						my $watchdog_str = "";
						$watchdog_str .= "$prefix    WATCHDOG " . __FILE__ . ":". __LINE__;
						$watchdog_str .= "  root $rid";
						$watchdog_str .= ", chain_len $chain_len";
						$watchdog_str .= ", md5 $issuer_md5_cnt/$issuer_md5_cnt_total";
						$watchdog_str .= ", on avg $avg_sec_per_md5 sec/md5";
						$watchdog_str .= ", cert $cert_cnt/$cert_cnt_total";
						$watchdog_str .= ", on avg $avg_sec_per_cert sec/cert";
						$watchdog_str .= ", cert id: " . $cert->id;
						say $watchdog_str;
						$watchdog_certs_for_md5_timeout = $cur_time + $watchdog_timeout_seconds;
					}
				}  # validation (via subworker or in this thread)

			}  # for my $cert ... end

		}  # for my $issuer_md5 ... end

		if ($self->nsubworker > 1) {
			$intermediates_subworker_queue->end();

			say "$prefix\t Waiting for subworker to finish (chain_len $chain_len)";
			while(1) {
				select(undef, undef, undef, 5);

				my @running_subworker;
				my @joinable_subworker;
				for my $thr (@intermediates_subworker_threads) {
					if ($thr->is_running()) {
						push(@running_subworker, $thr);
					}
					if ($thr->is_joinable()) {
						push(@joinable_subworker, $thr);
					}
				}

				unless (scalar @running_subworker) {
					last;
				}

				my $cur_time = time;
				if ($cur_time > $watchdog_timeout) {
					my $certs_in_queue_cnt = $intermediates_subworker_queue->pending();
					$certs_in_queue_cnt = 0 unless (defined $certs_in_queue_cnt);
					my $certs_processed_by_workers = $certs_offloaded_to_workers - $certs_in_queue_cnt;
					my $avg_time_per_cert = ($certs_processed_by_workers != 0) ? ($cur_time - $time_chain_len_started) / $certs_processed_by_workers : "n/a";
					my $running_threads_cnt = scalar @running_subworker;
					my $str_running_threads = join(' ', map {$_->tid} @running_subworker);
					my $joinable_threads_cnt = scalar @joinable_subworker;
					my $str_joinable_threads = join(' ', map {$_->tid} @joinable_subworker);
					my $watchdog_str = "";
					$watchdog_str .= "$prefix\t WATCHDOG " . __FILE__ . ":". __LINE__;
					$watchdog_str .= "  root $rid";
					$watchdog_str .= ", chain_len $chain_len";
					$watchdog_str .= ", certs\@Queue $certs_in_queue_cnt (total: $certs_offloaded_to_workers; ~ $avg_time_per_cert s/cert)";
					$watchdog_str .= ", running subworker: $running_threads_cnt ($str_running_threads)";
					$watchdog_str .= ", joinable subworker: $joinable_threads_cnt ($str_joinable_threads)";
					say $watchdog_str;
					$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
				}
			}

			for my $thr (@intermediates_subworker_threads) {
				my $subworker_validcerts_cnt = $thr->join();
				if (my $err = $thr->error()) {
					croak("$prefix\t subworker error (chain_len $chain_len): $err\n");
				}
				unless (defined $subworker_validcerts_cnt) {
					croak("$prefix\t undefined return by subworker (chain_len $chain_len)\n");
				}
				if ($subworker_validcerts_cnt > 0) {
					$validcerts_cnt += $subworker_validcerts_cnt;
					$stable = 0;
				}
			}
			say "$prefix\t All subworker finished for chain_len $chain_len";
		}

		# finished with current $chain_len
		if ($self->track_cachain_state) {
			$rid_validationstate->partial_state_chainlen($chain_len);
			$rid_validationstate->save;
		}

		goto LOOP if ( !$stable );

		# fully done
		if ($self->track_cachain_state) {
			$rid_validationstate->verified_at(time2str("%Y-%m-%d %H:%M:%S", time, "UTC"));
			$rid_validationstate->save;
		}

		say "$prefix finished for rootstore $rid.";
	}


	# Serialize the gathered information for reimport at the parent
	my $res = $self->populate_intermediates_export(@handled_rids);

	# It appears dangerous to pass a hash reference via the queue, however, this
	# seems to be supported: "Passing array/hash refs that contain objects may
	# not work for Perl prior to 5.10.0."
	# https://metacpan.org/pod/Thread::Queue#LIMITATIONS
	#
	# Note that the use of a queue instead of 'return' was created as means of
	# a workaround, when lacking knowledge that the return context of a thread
	# is determined at ->create() and explicitly set to the context of the
	# ->create() call when not explicitly set. When implementing the feature (and
	# apparently still as time of writing), we call ->create() in void context
	# such that ->join() returns void.
	# Further infos: https://metacpan.org/pod/threads#THREAD-CONTEXT
	# That said, it may or may not work to use 'return $res' when explicitly
	# setting the thread’s context to {'context' => 'scalar'}. However, in contrast
	# to Thread::Queue, the threads documentation does not state if it is safe
	# to pass references via 'return'.
	$results_queue->enqueue($res);

	say "$prefix finished.";

}

sub populate_intermediates_subworker {
	my ($self, $common_prefix, $rid, $chain_len, $rid_validationstate, $intermediates_subworker_queue) = @_;
	CertReader::App::VerifyCerts->reconnect_db_handlers($self);
	my $prefix = "$common_prefix (tid " . threads->self()->tid() . "):";
	my $croot = $self->ca->{$rid};
	my $certs_by_id = $croot->get_cache_certs_by_id;
	my $validcerts_cnt = 0;

	say "$prefix started (rid $rid, chain_len $chain_len).";

	my $possiblechains_cnt;
	my $current_cert_issuer_md5;
	my $last_cert_issuer_md5;
	while ( my $cert_id = $intermediates_subworker_queue->dequeue() ) {
		my $cert = $certs_by_id->{$cert_id};
		$current_cert_issuer_md5 = CertReader::DB::CaChain::Manager->_cert_issuer_md5($cert);

		my $possiblechains_cnt_requires_update = 0;
		if (defined $possiblechains_cnt) {
			if (defined $last_cert_issuer_md5) {
				$possiblechains_cnt_requires_update = 1 unless ($current_cert_issuer_md5 eq $last_cert_issuer_md5);
			} else {
				$possiblechains_cnt_requires_update = 1;
			}
		} else {
			$possiblechains_cnt_requires_update = 1;
		}

		if ($possiblechains_cnt_requires_update) {
			$possiblechains_cnt = $croot->get_chains_cnt_for_cert($cert, $chain_len);
		}


		my $watchdog_state_str = "";
		$watchdog_state_str .= "  root $rid";
		$watchdog_state_str .= ", chain_len $chain_len";
		my $found_valid_chain = $self->_validate_cert($rid, $cert, $chain_len, $possiblechains_cnt, $prefix, $watchdog_state_str, $rid_validationstate);
		if (defined $found_valid_chain) {
			if ($found_valid_chain) {
				$validcerts_cnt += 1;

				# TODO we would need to push the valid cert_ids to a queue
				# However, we do not use the feature $limited_path_analysis anymore,
				# thus simply remove when refactoring
				# if ($self->limited_path_analysis) {
				# 	$fp{$cert->fingerprint_sha1} = 1;
				# }
			}
		}

		$last_cert_issuer_md5 = $current_cert_issuer_md5;
	}

	say "$prefix finished (rid $rid, chain_len $chain_len).";
	return $validcerts_cnt;
}

sub _validate_cert {
	# returns undef if validation was skipped
	# returns 1 if validation was performed and a valid chain was found
	# returns 0 if validation was performed and no valid chain was found
	my ($self, $rid, $cert, $chain_len, $possiblechains_cnt, $prefix, $watchdog_state_str, $rid_validationstate) = @_;

	my $cert_validationstatus_in_rid = CertReader::DB::ValidationStateRootcert::SubstateCert::Manager->get_vs_cert_in_rootcert_for_rid_and_cert($rid, $cert);
	if ($cert_validationstatus_in_rid) {
		if (defined $cert_validationstatus_in_rid->partial_state_chainlen) {
			if ($cert_validationstatus_in_rid->partial_state_chainlen >= $chain_len) {
				if (str2time($cert_validationstatus_in_rid->partial_state_started_at, "GMT") >= str2time($rid_validationstate->partial_state_started_at, "GMT")) {
					say "$prefix Skipping cert id $cert->{id}: chainlen $chain_len <= $cert_validationstatus_in_rid->{partial_state_chainlen} (rid $rid)";
					return undef;
				} else {
					$cert_validationstatus_in_rid->partial_state_started_at($rid_validationstate->partial_state_started_at);
					$cert_validationstatus_in_rid->partial_state_chainlen(undef);
					$cert_validationstatus_in_rid->partial_state_cachain(undef);
					$cert_validationstatus_in_rid->partial_state_found_valid_chain(undef);
					$cert_validationstatus_in_rid->save;
				}
			}
		}
	} else {
		$cert_validationstatus_in_rid = CertReader::DB::ValidationStateRootcert::SubstateCert->new(rootcert_id => $rid, cert_id => $cert->id);
		$cert_validationstatus_in_rid->partial_state_started_at($rid_validationstate->partial_state_started_at);
		$cert_validationstatus_in_rid->save;
	}

	if ($self->skip_certs_with_count_valid_cachains_for_rootcert > 0) {
		my $croot = $self->ca->{$rid};
		my $count = $self->skip_certs_with_count_valid_cachains_for_rootcert;
		if ($croot->cert_is_leaf_of_count_cachains($cert, $count)) {
			say "$prefix WARNING Skipping cert id $cert->{id}: chainlen $chain_len (rid $rid) -- Already has $count chains to root";
			return undef;
		}
	}

	# test if we can read the cert public key.
	my $openssl = $cert->openssl;
	my $key_mod = $cert->key_mod;
	# if we don't have it, use serial... :/
	$key_mod //= $cert->serial;
	# When not in thorough mode (i.e., CertReader::App::VerifyCerts->verifyall)
	# we can skip an intermediate certificate if we know that it is not valid
	# for a root store as there won't be any such paths.
	# In thorough mode (i.e., CertReader::App::VerifyCerts->verifycas) we don't skip
	# to check for a valid path to the root.
	# next if ( !$self->thorough && !$cert->valid($attime_dt)->contains($rid) );

	my $write_to_db = 1;
	my $found_valid_chain = $self->validateChainSingle($cert, $rid, $self->attime, $chain_len, $prefix, $possiblechains_cnt, $write_to_db, $watchdog_state_str, $cert_validationstatus_in_rid);
	# my @valid = $self->validateChainSingle($cert, $rid, $self->attime, $chain_len, $prefix, $possiblechains);
	# if ( scalar @valid > 0 ) {
	# 	$validcerts_cnt += 1;
	# 	# say "$prefix     WATCHDOG already $validcerts_cnt valid certs with chainlen $chain_len for rootstore $rid  - current cert: " . $cert->id if ($validcerts_cnt % 100 == 0);
	# 	# say "$prefix WARNING large chain_len $chain_len (rootstore $rid) - valid cert: " . $cert->id if ($chain_len > 1 and $chain_len % 100 == 0);
	# 	$stable = 0;
	# 	for my $chain (@valid) {
	# 		push(@validcerts, [$cert, $chain]);
	# 	}

	# 	if ($self->limited_path_analysis) {
	# 		$fp{$cert->fingerprint_sha1} = 1;
	# 	}
	# }

	# # and now actually add them to the store so that they will be used during validation
	# # in the next round...
	# # TODO  As add_chain_certs now writes to the DB, maybe push this down to ->validateChainSingle to free up memory as early as possible
	# my $entry_cnt = 0;
	# my $entry_cnt_total = scalar @validcerts;
	# my $watchdog_paths_for_cert_timeout = time + $watchdog_timeout_seconds;
	# my $watchdog_paths_for_cert_starttime = time;
	# for my $entry (@validcerts) {
	# 	$entry_cnt += 1;

	# 	my $cert = $entry->[0];
	# 	my $chain = $entry->[1];
	# 	# remove last - is rootcert;
	# 	# pop @{$chain->openssl};
	# 	pop @{$chain->cert_ids};

	# 	$croot->add_chain_certs($cert, $chain, $self->limited_path_analysis);
	# 	# print "$prefix rootstore $rid - adding chain for cert_id " . $cert->id . "("; for my $c (@{$chain->certs}) {print $c->id . ".";} say ")"; # DEBUG

	# 	$cur_time = time;
	# 	if ($cur_time > $watchdog_paths_for_cert_timeout) {
	# 		my $avg_sec_per_md5 = $issuer_md5_cnt > 1 ? ($cur_time - $watchdog_rid_starttime) / ($issuer_md5_cnt - 1) : "n/a";
	# 		my $avg_sec_per_path = ($cur_time - $watchdog_paths_for_cert_starttime) / $entry_cnt;
	# 		my $watchdog_str = "";
	# 		$watchdog_str .= "$prefix    WATCHDOG " . __FILE__ . ":". __LINE__;
	# 		$watchdog_str .= "  root $rid";
	# 		$watchdog_str .= ", chain_len $chain_len";
	# 		$watchdog_str .= ", md5 $issuer_md5_cnt/$issuer_md5_cnt_total";
	# 		$watchdog_str .= ", on avg $avg_sec_per_md5 sec/md5";
	# 		$watchdog_str .= ", cert $cert_cnt/$cert_cnt_total";
	# 		$watchdog_str .= ", writing paths to DB: $entry_cnt/$entry_cnt_total";
	# 		$watchdog_str .= ", on avg $avg_sec_per_path sec/path";
	# 		$watchdog_str .= ", cert id: " . $cert->id;
	# 		say $watchdog_str;
	# 		$watchdog_paths_for_cert_timeout = $cur_time + $watchdog_timeout_seconds;
	# 	}
	# }
	# @validcerts = ();


	# finished with current cert
	if ($self->track_cachain_state) {
		$cert_validationstatus_in_rid->partial_state_chainlen($chain_len);
		$cert_validationstatus_in_rid->partial_state_cachain(undef);
		$cert_validationstatus_in_rid->partial_state_found_valid_chain(undef);
		$cert_validationstatus_in_rid->save;
	}

	return $found_valid_chain;
}


sub populate_intermediates_export {
	my ($self, @handled_rids) = @_;

	return {};  # not needed anymore as we store the chains in the DB

	# This will store the updates to the rootstores such that we can replay them in the workers parent.
	# Basically, we just store the added chains by means of the ids of the certificates
	# TODO We may explore more efficient transmission of rootstore data to the parent. However, not messing with pointers and
	# the link of objects to Rose::DB seems to be not straightforward.
	my $w_res = {};
	for my $rid (@handled_rids) {
		my $croot = $self->ca->{$rid};
		$w_res->{$rid} = {};
		for my $subject (keys %{$croot->chains}) {
			$w_res->{$rid}{$subject} = {};
			$w_res->{$rid}{$subject}{chains} = [];
			for my $chain (@{$croot->{chains}{$subject}{chains}}) {
				my @marshalled_chain = @{$chain->cert_ids};
				push(@{$w_res->{$rid}{$subject}{chains}}, \@marshalled_chain);
			}
		}
	}
	return $w_res;
}

sub populate_intermediates_import {
	my ($self, $w_res) = @_;

	for my $rid (keys %$w_res) {
		my $croot = $self->ca->{$rid}; # our target for import
		for my $subject (keys %{$w_res->{$rid}}) {
			for my $marshalled_chain (@{$w_res->{$rid}{$subject}{chains}}) {
				# my $chain_openssl = [];
				my $chain_cert_ids = [];
				for my $cert_id (@$marshalled_chain) {
					# my $cert = CertReader::DB::Certificate->new(id => $cert_id);
					# $cert->load();
					# push(@$chain_openssl, $cert->openssl);
					push(@$chain_cert_ids, $cert_id);
				}
				my $chain = CertReader::CA::Chain->new(
					rid => $rid,
					store => $croot->store,
					# openssl => $chain_openssl,
					cert_ids => $chain_cert_ids,
				);
				if (scalar @$chain_cert_ids == 0) {
					next; # TODO genuine?
				}
				my $leafcert = CertReader::DB::Certificate->new(id => @$chain_cert_ids[0]);
				$leafcert->load();
				# Now mimic the actions performed with chains in @validcerts in the worker thread
				# pop @{$chain->openssl}; # this was already done by the worker
				# pop @{$chain->cert_ids}; # this was already done by the worker
				# print "Parent: rootstore $rid - adding chain for cert_id " . $leafcert->id . "("; for my $c (@{$chain->certs}) {print $c->id . ".";} say ")"; # DEBUG
				$croot->add_chain_certs($leafcert, $chain, $self->limited_path_analysis);
			}
		}
	}
}

=blob ca searching:
	opendir(my $dh, $self->dir) || croak("cannot opendir ".$self->dir);

	# sorry for the next line. get all ca files in the ca directory, strip extention and sort them by timestamp.
	my @timestamps = sort { $a <=> $b } map { s/\.ca$//; $_ } grep { /^(\d+)\.ca$/ && -f $self->dir."/$_" } readdir($dh);

	croak ("No files in ".$self->dir."?") unless ( scalar @timestamps > 0 );

	# find fitting filename...

	my $cats = shift @timestamps;

	for my $ts ( @timestamps ) {
		if ( $self->timestamp >= $ts ) {
			# take it!
			$cats = $ts;
		} else {
			# well... we overshot, our timestamp is < then all remaining cas.
			last;
		}
	}

	$cats = $self->dir."/$cats.ca";
	$self->cafile($cats);


	open ( my $fh, "<", $cats );

=blob nss certificate loading:
	$x509 = Crypt::NSS::X509::Certificate->new_from_pem($cert) or croak("could not parse cert");

=blob NSS store loading:
	# import rootstore into NSS. Only required once - after that it is in the DB.
	#Crypt::NSS::X509->load_rootlist($self->cafile);

	# Load the internal list of trusted builtins (NSSCBKI). Because NSS does not offer any way to find this library,
	# you need to know its path (oh fun). Or if there is a to load it without knowing the paths, I could not find it.
	# In any case, this is embarassingly stupid, I am sorry, and I have no idea how to get around it :(
	my @ckbipaths = qw#/home/bernhard/perl/lib/site_perl/5.16.1/auto/share/dist/Alien-NSS/lib/libnssckbi.so
			   /home/bernhard/sw/lib/perl5/site_perl/5.16.2/auto/share/dist/Alien-NSS/lib/libnssckbi.so
			   /home/bernhard/sw/lib/perl5/site_perl/5.18.2/auto/share/dist/Alien-NSS/lib/libnssckbi.so
			   /Users/bernhard/sw/lib/perl5/site_perl/5.18.2/auto/share/dist/Alien-NSS/lib/libnssckbi.dylib#;


	for my $try (@ckbipaths) {
		if (-f $try) {
			Crypt::NSS::X509::__add_builtins($try);
			return;
		}
	}

	# if we are here, we could not find a valid builtin library
	croak("Could not find nssckbi.so. Please check paths in CA.pm");

=blob NSS intermediate loading

	# an now try to add them to Crypt::NSS::X509
	my @rejectedcerts;
	my $i = 0;
	for my $cert (@$certificate) {
		my $nsscert;
		eval {
			$nsscert = Crypt::NSS::X509::Certificate->new($cert->der);
		} or do {
			say STDERR "Certificate parsing failed: $@";
			say STDERR "For certificate: ".$cert->subject." ".$cert->cert_hash." ".$cert->issuer;
			next;
		};

		my $res = $nsscert->verify_cert($ts, 11); #Crypt::NSS::X509::certUsageAnyCA);
		if ( $res == 1 ) {
			say STDERR "Accepted .".$cert->subject." ".$cert->cert_hash." ".$cert->issuer;
			Crypt::NSS::X509::add_cert_to_db($nsscert, "intermediate-$i");
			$i++;
		} else {
			say STDERR "Rejected .".$cert->subject." ".$cert->cert_hash." ".$cert->issuer;
			push(@rejectedcerts, $cert);
		}
	}

	# ok, and now - recurse
	$self->checkRejectedIntermediates(\@rejectedcerts, $i, $ts);

sub checkRejectedIntermediates {
	my ($self, $rejected, $i, $ts) = @_;

	my $starti = $i;

	my @newrejected;
	for my $lcert ( @$rejected ) {
		my $cert;
		eval {
			$cert = Crypt::NSS::X509::Certificate->new($lcert->der);
		} or do {
			say STDERR "Certificate parsing failed: $@";
			say STDERR "For certificate: ".$lcert->subject." ".$lcert->cert_hash." ".$lcert->issuer;
			next;
		};


		my $res = $cert->verify_cert($ts, 11); #Crypt::NSS::X509::certUsageAnyCA);

		if ( $res == 1 ) {
			Crypt::NSS::X509::add_cert_to_db($cert, "intermediate-$i");
			$i++;
		} else {
			push(@newrejected, $lcert);
		}
	}

	if ( $i > $starti ) {
		$self->checkRejectedIntermediates(\@newrejected, $i, $ts);
	} else {
		say STDERR "Finally rejected ".(scalar @$rejected)." certificates";
	}
}

=cut

1;
