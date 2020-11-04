package CertReader::App::EvalCrosssign;

# Find and output cross-signs

use forks; # ALWAYS LOAD AS FIRST MODULE, if possible
# Tell Forks::Queue to not play signal bomb
# Alternatively to disabling signals for queue signaling is to ensure a sufficiently
# Large stepsize such that not too many elements are withdrawn from the queue while
# a thread blocks, e.g., while waiting for response of the database. However, calculating
# an appropriate stepsize is quite system and situation dependent.
BEGIN { $ENV{FORKS_QUEUE_NOTIFY} = 0; } # Tell Forks::Queue to not play signal bomb
use Forks::Queue;
my $nworker = 5;
my $stepsize = 10000;
use Thread::Semaphore;
my $semaphore_table_write_cross_sign_candidate = Thread::Semaphore->new(1);

use 5.14.1;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use FileHandle;
use List::Util qw[min max];
use Date::Format qw[time2str];

use open ':std', ':encoding(UTF-8)';
use Scalar::Util;
use POSIX;

use Moose;

use Crypt::OpenSSL::X509;

use CertReader::DB::CrossSignCandidate;
use CertReader::DB::VerifyTree;
with 'CertReader::Base';
with 'CertReader::CA';
with 'CertReader::CertCache';

my $label_to_category_helper = {
	'android' => 'android',
	'FF' => 'mozilla',
	'ms-' => 'microsoft',
	'ios' => 'apple',
	'osx' => 'apple',
	'grid-igtf' => 'grid',
	'us_fpki' => 'usa',
	'swiss_gov' => 'swiss',
	'nl_gov' => 'netherlands',
	'au_gov' => 'australia',
	'india_gov' => 'india',
	'oman_gov' => 'oman',
	'japan_gov' => 'japan',
	'estonia_sk' => 'estonia',
	# rootstore labels in legacy databases
	'microsoft' => 'microsoft',
	'mozilla' => 'mozilla',
	'grid_igtf' => 'grid',
};

sub label_to_category {
	my $label = shift;

	for my $key (keys %$label_to_category_helper) {
		if (index($label, $key) > -1) {
			return $label_to_category_helper->{$key};
		}
	}

	croak("Error: Cannot find category for label $label");
}

sub get_rootstore_categories_cnt {
	my %rootstore_categories;
	my $rootstore_categories_cnt = 0;
	for my $label (keys %$label_to_category_helper) {
		my $category = $label_to_category_helper->{$label};
		if (! defined $rootstore_categories{$category}) {
			$rootstore_categories_cnt += 1;
			$rootstore_categories{$category} = 1;
		}
	}
	return $rootstore_categories_cnt;
}

has 'nworker' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $nworker,
	documentation => "Number of threads. Default: $nworker",
);

has 'stepsize' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $stepsize,
	documentation => "Maximum number of lines requested from the database in one query. Default: $stepsize",
);

has 'resultsdir' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	default => "./",
	documentation => "Select a parent directory that will be used to create the directory that will contain the results (default: .)",
);

has 'with_san_lists' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Consider SAN lists when looking for cross-sign certs.',
);

has 'with_aki_ext_eval' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Check aki and corresponding ski for inconsistencies.',
);

has 'ignore_invalid' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Ignore certificates that do not have a valid path.',
);

has 'ca_certs_only' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Ignore certificates that cannot issue certificates.',
);

has 'known_XScerts_only' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Read the csc ids from csc_metadata_full --> not looking for new; Implies skip_database_update',
);

has 'skip_database_update' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Do not update cross-sign certificate candidates in the database. May result in outdated results.',
);

has 'only_database_update' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Only update cross-sign certificate candidates in the database. Do not run final evaluation.',
);

has 'start_with_certid' => (
	is => 'rw',
	isa => 'Int',
	required => 0,
	default => 0,
	documentation => "Skip all certificates with id smaller than given. Usually only needed to resume work. Only effective for cross-sign certificate candidates DB updates.",
);

has 'legacy_rootstore_eval' => (
	is => 'ro',
	isa => 'Bool',
	required => 0,
	default => 0,
	documentation => 'Run the legacy rootstore eval. Default: 0 (No)',
);

has 'debug_csc_preprocessing' => (
	is => 'ro',
	isa => 'Bool',
	required => 0,
	default => 0,
	documentation => 'Additional debug output when filling cross sign candidate tables',
);

has 'debug_rootstore_coverage' => (
	is => 'ro',
	isa => 'Bool',
	required => 0,
	default => 0,
	documentation => 'Additional debug output when calculating rootstore coverage',
);

has 'verbosity' => (
	is => 'rw',
	isa => 'Int',
	default => 0,
	documentation => 'Verbosity of log output',
);

has 'ignore_google_ct_precert_signing_certs' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Exclude certificates with the whose subject contains: Google Certificate Transparency (Precert Signing).',
);

has 'skip_evaluated_cscs' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Skip all cscids that have been evaluated at some time',
);

has 'ignore_evaluated_cscs' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Ignore all cscids that have been evaluated at some time (do not even iterate over them). Prefer this over skip_evaluated_cscs if most XS-certs have been evaluated already. Implies skip_evaluated_cscs = 1',
);

has 'gather_stats' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Gather stats, possibly memory exhaustive (Disabled by default)',
);

has 'timestamp_start' => (
	is => 'ro',
	isa => 'Str',
	default => sub { POSIX::strftime("%F_%Hh-%Mm-%Ss%z", localtime()) },
	documentation => 'Timestamp at time of script startup',
);

sub cmp_num_or_str {
	my ($a, $b, $va, $vb) = @_;
	if (Scalar::Util::looks_like_number($a) and Scalar::Util::looks_like_number($b)) {
		# Note: as $a and $b are keys in the same array, they must differ
		return $a <=> $b;
	}
	if (Scalar::Util::looks_like_number($va) and Scalar::Util::looks_like_number($vb) and $va != $vb) {
		return $va <=> $vb;
	}
	return $a cmp $b;
}


sub populate_rootstore_cache {
	my $self = shift;

	$self->{'rootstore_cache'} = {};

	say "Populating rootstores...";
	my $rootcerts = CertReader::DB::RootCerts::Manager->get_rootcerts(db => $self->db);
	for my $rootcert ( sort {$a->id <=> $b->id} @$rootcerts ) {

		$self->{'rootstore_cache'}->{$rootcert->id} = $rootcert;
		# Obtain meta information now such that we can use cached results later
		my $rootcert_info = $rootcert->get_info_by_rootstore;

		if ($self->verbosity > 1) {
			my $str = "$rootcert->{id}:\n";
			for my $rootstore_name (sort keys %$rootcert_info) {
				my $valid = $rootcert_info->{$rootstore_name}->{'valid'};
				$str .= "\t$rootstore_name : $valid (";
				$str .= $rootcert_info->{$rootstore_name}->{'validity_periods'}->to_string;
				$str .= ")\n";
			}
			print $str;
		}

	}
}


# TODO attime support?
sub run {
	my $self = shift;

	if ($self->ignore_google_ct_precert_signing_certs) {
		croak("--ignore_google_ct_precert_signing_certs not implemented.");
	}

	if ($self->known_XScerts_only) {
		$self->skip_database_update(1);
	}

	if ($self->ignore_evaluated_cscs) {
		$self->skip_evaluated_cscs(1);
	}

	STDOUT->autoflush(1);
	STDERR->autoflush(1);

	say "Startup time: " . $self->timestamp_start;

	$self->populate_rootstore_cache;
	$self->populate_cs_cert_candidates;

	$self->{log_dir} = $self->resultsdir . "/EvalCrosssign_logs_" . $self->timestamp_start;
	if ($self->skip_evaluated_cscs) {
		$self->{log_dir} .= "_continued";
	}
	say "Creating directory " . $self->{log_dir} . " for logs";
	croak("Could not create directory " . $self->{log_dir} . ": $!") if !mkdir($self->{log_dir});

	my $log = $self->{log_dir} . "/log.txt";
	$self->{fh_log} = FileHandle->new($log, '>:encoding(UTF-8)');
	croak("Could not open $log") if !defined($self->{fh_log});
	$self->{fh_log}->autoflush(1);

	my $log_python = $self->{log_dir} . "/EvalCrosssign_results.py";
	$self->{fh_results_python} = FileHandle->new($log_python, '>:encoding(UTF-8)');
	croak("Could not open $log_python") if !defined($self->{fh_results_python});
	$self->{fh_results_python}->autoflush(1);

	my $stats = $self->run_eval;

	if ($self->gather_stats) {
		say "\n\nEval statistics: {";
		say {$self->{fh_log}} "\n\nEval statistics: {";
		say {$self->{fh_results_python}} "#!/usr/bin/env python\n# -*- coding: utf-8 -*-\n";
		say {$self->{fh_results_python}} "evalcrosssign_results = {";
		for my $statistic (sort keys %{$stats}) {
			my $value = $stats->{$statistic};
			if (ref($value) eq "HASH") {
				my $str = "\t\"$statistic\": {\n";
				for my $key (sort { cmp_num_or_str($a, $b, $value->{$a}, $value->{$b}) } keys %$value) {
					my $subvalue = $value->{$key};
					$str .= "\t\t\"" . (join "\n\t\t", (split "\n", $key, -1)) . "\": $subvalue,\n"
				}
				$str .=	"\t},";
				say "$str";
				say {$self->{fh_log}} "$str";
				say {$self->{fh_results_python}} "$str";
			} else {
				my $str = "\t\"$statistic\": " . $value . ",";
				say "$str";
				say {$self->{fh_log}} "$str";
				say {$self->{fh_results_python}} "$str";
			}
		}
		say "}";
		say {$self->{fh_results_python}} "}";
	}

	exit(0);
}

sub disconnect_db_handlers {
	# This function must be called before forking!
	# Otherwise, the clients will close the database handle such that the parent
	# fails upon its next usage of the database connection. Hence, we close all
	# DB connections before a fork, and restore them afterwards such that the parent
	# and each worker have their own database handles.
	# Note that InactiveDestroy and AutoInactiveDestroy seem to be unsuitable as
	# Rose::DB actively calls 'disconnect' on the handler, which still causes the
	# connection to be closed: https://metacpan.org/pod/DBI#InactiveDestroy

	my ($class, $self) = @_;

	my $db_objects = CertReader::DB->new_or_cached;
	my $db_orm = $self->db; # This was generated by CertReader::ORM
	$db_objects->dbh->disconnect;
	$db_orm->dbh->disconnect;

	my $disconnect_cnt = 2; # The number of disconnects triggered above

	# Sanity check if there are more db handlers than expected.
	# Note that we can find them this way, but as they are most probably generated
	# by Rose::DB we need to find the corresponding Rose::DB objects to be able
	# to reconnect them afterwards (see reconnect_db_handlers()), sorry.
	my %dbi_drivers = DBI->installed_drivers();
	my @parent_dbh = grep { defined } map { @{$_->{ChildHandles}} } values %dbi_drivers;
	if (scalar @parent_dbh > $disconnect_cnt) {
		croak("Found more dbi handlers than we closed");
	}
}

sub reconnect_db_handlers {
	# Reconnect the database using new generated connections.
	my ($class, $self) = @_;

	my $db_objects = CertReader::DB->new_or_cached;
	my $db_orm = $self->db;

	my $new_dbh_objects = CertReader::DB->new()->retain_dbh
		or die Rose::DB->error;
	$db_objects->dbh($new_dbh_objects);
	my $new_dbh_orm = CertReader::DB->new()->retain_dbh
		or die Rose::DB->error;
	$db_orm->dbh($new_dbh_orm);
}

sub is_certid_valid {
	my ($self, $certid) = @_;
	my $postfix = $self->tablepostfix;

	my $vts = CertReader::DB::VerifyTree::Manager->get_verifypaths_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "select * from verify_tree_$postfix where certificate = $certid LIMIT 1;",
	);
	if (scalar @$vts) {
		return 1;
	} else {
		return 0;
	}
}

sub populate_cs_cert_candidates {
	my $self = shift;
	my $postfix = $self->tablepostfix;
	my $batchsize = $self->stepsize;

	if ($self->ca_certs_only) {
		croak("Option ca_certs_only not supported anymore!");
	}

	if ($self->skip_database_update) {
		say "WARNING Skipping update of cross-sign related database tables. Results may be outdated."
	} else {
		say "Iterating over all certificates to update cross-sign related database tables";

		my $certid_max = CertReader::DB::Certificate::Manager->get_certificate_id_max($self->db, $self->tablepostfix);

		my $currid = 0;
		my $lastid = -1;
		say "\tWe will iterate over a total of $certid_max certificates in batches of $batchsize.";

		if ($self->start_with_certid) {
			$currid = $self->start_with_certid;
			say "\t\tSkipping certificates with id < $currid.";
		}

		my $certbatch_queue = Forks::Queue->new( impl => 'Shmem' );
		while( $lastid < $certid_max ) {
			$lastid = min($currid + ($batchsize - 1), $certid_max);
			$certbatch_queue->enqueue([$currid, $lastid]);
			$currid = $lastid + 1;
		}
		$certbatch_queue->end();

		CertReader::App::EvalCrosssign->disconnect_db_handlers($self);
		for ( 1 .. $self->nworker ) {
			threads->create( {'context' => 'list'}, \&populate_cs_cert_candidates_worker, $self, $certbatch_queue );
		}

		say "Waiting for worker to finish their work ...";
		foreach my $thr ( threads->list() ) {
			my $ret = $thr->join();
			if (!defined($ret)) {
				croak("error in populate_cs_cert_candidates_worker: Exited abnormally")
			}
			if ($ret != 0) {
				croak("error in populate_cs_cert_candidates_worker: $ret")
			}
			if (my $err = $thr->error()) {
				croak("MAIN THREAD: ERROR in worker $thr->{tid}: $err\n");
			}
		}
		say "All worker finished";

		CertReader::App::EvalCrosssign->reconnect_db_handlers($self);
		say "\tdone.";
	}

	if ($self->only_database_update) {
		say "Stopping as only update of candidates was requested (--only_database_update)";
		exit(0);
	}
}

sub add_csc_cert_unique {
	my ($self, $csc, $cert) = @_;

	my $csc_cert = CertReader::DB::CrossSignCandidateCert::Manager->get_csc_cert_for_csc_and_cert($self->db, $self->tablepostfix, $csc, $cert);
	if (!$csc_cert) {
		$csc_cert = CertReader::DB::CrossSignCandidateCert->new(
			csc_id => $csc->id,
			cert_id => $cert->id,
			from_subj_alt_ext => 0,
			);
		$csc_cert->save;
	}

	if ($self->with_san_lists) {
		# TODO add entries for certificate based on SAN list; see old code below
		croak("with_san_lists not implemented")
	}
}

sub populate_cs_cert_candidates_worker {
	my ($self, $certbatch_queue) = @_;
	my $postfix = $self->tablepostfix;
	my $prefix = "Worker " . threads->self()->tid() . ":";
	say "$prefix started.";

	CertReader::App::EvalCrosssign->reconnect_db_handlers($self);

	while ( my $in = $certbatch_queue->dequeue() ) {
		my ($currid, $lastid) = @$in;

		say "\t" . localtime() . "    $prefix analyzing certs $currid - $lastid";

		my $sql = "select * from certificate_$postfix where id >= $currid and id <= $lastid order by id asc;";
		my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);

		my @db_write_queue;

		while ( my $cert = $certiter->next ) {
			if (!defined($cert->subject) or !defined($cert->key_mod)) {
				next;
			}

			my $csc = CertReader::DB::CrossSignCandidate::Manager->get_crosssigncandidate_for_cert($self->db, $self->tablepostfix, $cert);
			if (!$csc) {
				push @db_write_queue, $cert;	# Queue for later as this needs a DB lock
			} else {
				# Adding csc_cert entries is safe without locking as this thread is the only one handling this specific certificate
				$self->add_csc_cert_unique($csc, $cert);
			}

		}

		# Now get the DB-table write lock and do the write work
		my $db_write_queue_len = scalar @db_write_queue;
		if ($db_write_queue_len > 0) {
			# We need to add a new entry, but other worker might want to add
			# the same entry at the same time. Thus we need to lock the DB
			say "\t" . localtime() . "    $prefix ---> WAIT LOCK (writing $db_write_queue_len certs) <---";
			$semaphore_table_write_cross_sign_candidate->down();
			# say "\t" . localtime() . "    $prefix ---> GOT LOCK (writing $db_write_queue_len certs) <---";
			my @db_cscCert_write_queue;
			for my $cert (@db_write_queue) {

					# The entry might have been added while we waited for the lock
					# Thus, do the check again
					my $csc = CertReader::DB::CrossSignCandidate::Manager->get_crosssigncandidate_for_cert($self->db, $self->tablepostfix, $cert);
					if (!$csc) {
						$csc = CertReader::DB::CrossSignCandidate->new(
							subject => $cert->subject,
							key_mod => $cert->key_mod,
							);
						$csc->save;
						if ($self->debug_csc_preprocessing) {
							say "\t\tnew csc id: " . $csc->id;
							say "\t\t\tsubject: " . $cert->subject;
							say "\t\t\tkey_mod: " . $cert->key_mod;
						}
					}

					# Adding csc_cert entries is safe without locking as this thread is the only one handling this specific certificate
					# Thus, we defer it after release of the lock
					push @db_cscCert_write_queue, [$csc, $cert];

			}
			# say "\t" . localtime() . "    $prefix ---> RELEASING LOCK (writing $db_write_queue_len certs) <---";
			# Done, we can unlock write access to the DB
			$semaphore_table_write_cross_sign_candidate->up();
			say "\t" . localtime() . "    $prefix ---> RELEASED LOCK (wrote $db_write_queue_len certs) <---";
			# Now add the new csc_cert entries
			for my $q_entry (@db_cscCert_write_queue) {
					my ($csc, $cert) = @$q_entry;

					# Adding csc_cert entries is safe without locking as this thread is the only one handling this specific certificate
					$self->add_csc_cert_unique($csc, $cert);
			}
		}

	}

	say "$prefix finished.";

	return 0;
}

sub run_eval {
	my $self = shift;
	my $postfix = $self->tablepostfix;
	my $batchsize = $self->stepsize;

	if ($self->ca_certs_only) {
		croak("Option ca_certs_only not supported anymore!");
	}

	my $cscidrange_queue = Forks::Queue->new( impl => 'Shmem' );
	if ($self->known_XScerts_only) {

		say "Adding all **known** cross-sign certificates to the queue...";
		my $sql = "select * from csc_metadata_$postfix order by csc_id asc;";
		my $csc_metadata_iter = CertReader::DB::CrossSignCandidateMetaData::Manager->get_csc_metadata_objs_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);

		my $batch_id = 0;
		my $batch_id_max = 0;
		while (my $csc_metadata_obj = $csc_metadata_iter->next) {
			$cscidrange_queue->enqueue([$batch_id, $batch_id_max, $csc_metadata_obj->csc_id, $csc_metadata_obj->csc_id]);
		}

	} elsif ($self->ignore_evaluated_cscs) {

		say "Adding all **not evaluated* cross-sign certificates to the queue...";
		# Note the LEFT join
		my $sql = "select csc.* from cross_sign_candidate_$postfix as csc left join csc_evalstate_$postfix as s on csc.id = s.csc_id where evaluated_at is Null order by csc_id asc;";
		my $csc_iter = CertReader::DB::CrossSignCandidate::Manager->get_crosssigncandidates_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);

		my $batch_id = 0;
		my $batch_id_max = 0;
		while (my $csc_obj = $csc_iter->next) {
			$cscidrange_queue->enqueue([$batch_id, $batch_id_max, $csc_obj->id, $csc_obj->id]);
		}

	} else {

		say "Iterating over all cross-sign candidates, i.e., (subject, key_mod)";
		my $cscid_max = CertReader::DB::CrossSignCandidate::Manager->get_crosssigncandidate_id_max($self->db, $self->tablepostfix);
		say "\tWe have a total of $cscid_max candidates, iterating over these in batches of $batchsize.";

		my $currid = 0;
		my $lastid = -1;

		my $batch_id = 1;
		my $batch_id_max = POSIX::ceil($cscid_max / $batchsize);
		while( $lastid < $cscid_max ) {
			$lastid = min($currid + ($batchsize - 1), $cscid_max);
			$cscidrange_queue->enqueue([$batch_id, $batch_id_max, $currid, $lastid]);
			$currid = $lastid + 1;
			$batch_id += 1;
		}

	}
	$cscidrange_queue->end();

	CertReader::App::EvalCrosssign->disconnect_db_handlers($self);
	for ( 1 .. $self->nworker ) {
		threads->create( {'context' => 'list'}, \&run_eval_worker, $self, $cscidrange_queue );
	}

	my $stats = {};

	say "Waiting for worker to finish their work ...";
	my $watchdog_timeout_seconds = 60;
	my $watchdog_timeout = time + $watchdog_timeout_seconds;
	while(scalar threads->list(threads::running)) {
		select(undef, undef, undef, 10);

		my $cur_time = time;
		if ($cur_time > $watchdog_timeout) {
			my $running_threads_cnt = scalar threads->list(threads::running);
			my $str_running_threads = join(' ', map {$_->tid} threads->list(threads::running));
			my $joinable_threads_cnt = scalar threads->list(threads::joinable);
			my $str_joinable_threads = join(' ', map {$_->tid} threads->list(threads::joinable));
			say "MAIN THREAD: running threads: $running_threads_cnt ($str_running_threads), joinable threads: $joinable_threads_cnt ($str_joinable_threads)";
			$watchdog_timeout = $cur_time + $watchdog_timeout_seconds;
		}
	}
	foreach my $thr ( threads->list() ) {
		my ($ret, $w_stats) = $thr->join();
		if (!defined($ret)) {
			croak("error in run_eval_worker: terminated abnormally")
		}
		if ($ret != 0) {
			croak("error in run_eval_worker: $ret")
		}
		if (my $err = $thr->error()) {
			croak("MAIN THREAD: ERROR in worker $thr->{tid}: $err\n");
		}
		merge_stats($stats, $w_stats);
	}
	say "All worker finished";

	CertReader::App::EvalCrosssign->reconnect_db_handlers($self);
	say "\tdone.";

	say "Finished Eval.";
	return $stats;
}

sub run_eval_worker {
	my ($self, $cscidrange_queue) = @_;
	my $postfix = $self->tablepostfix;
	my $tid = threads->self()->tid();
	my $prefix = "Worker $tid:";
	say "$prefix started.";

	my $log = $self->{log_dir} . "/log_worker${tid}.txt";
	$self->{fh_log} = FileHandle->new($log, '>:encoding(UTF-8)');
	croak("Could not open $log") if !defined($self->{fh_log});
	$self->{fh_log}->autoflush(1);

	my $w_stats_overall = {};

	while ( my $in = $cscidrange_queue->dequeue() ) {
		my ($batch_id, $batch_id_max, $currid, $lastid) = @$in;
		my $currid_start_backup = $currid;

		say "\t" . localtime() . "    $prefix analyzing cross_sign_candidates $currid - $lastid";
		my $skipped_already_evaluated_cscids_cnt = 0;

		my $batch_id_str = POSIX::sprintf("%0" . length($batch_id_max) . "d", $batch_id) . "_";
		my $batch_certs_str = "${currid}-${lastid}";
		if ($batch_id_max == 0) {
			$batch_id_str = "";
			if ($currid == $lastid) {
				$batch_certs_str = "${currid}";
			}
		}
		my $w_log_base = "$self->{log_dir}/${batch_id_str}${batch_certs_str}";

		my $w_log_cscerts = $w_log_base . "_cscerts.txt";
		my $w_log_cscerts_fh;

		my $w_log_subgroup_cscerts = $w_log_base . "_subgroup-cscerts.txt";
		my $w_log_subgroup_cscerts_fh;

		my $w_log_evalrootstore = $w_log_base . "_evalrootstore.txt";
		my $w_log_evalrootstore_fh;

		my $time_csccerts;
		my $time_subgroup_cscerts;
		my $time_populate_stats;
		my $time_eval_rootstores;
		my $time_eval_extension_authority_key_identifier;
		my $sql = "select * from cross_sign_candidate_$postfix where id >= $currid and id <= $lastid order by id asc;";
		my $csciter = CertReader::DB::CrossSignCandidate::Manager->get_crosssigncandidates_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);
		while (my $csc = $csciter->next) {
			my $time_start = time;
			my $csc_evalstate = CertReader::DB::EvalstateCrossSignCandidate->new( csc_id => $csc->id );
			if ($csc_evalstate->load( speculative => 1 )) {
				# TODO Add new default: only reevaluated if new verify_trees exist, also think about other triggers for reevaluation
				if ($self->skip_evaluated_cscs) {
					# say "\t" . localtime() . "    $prefix  Skipping csc_id $csc->{id} as already evaluated";
					$skipped_already_evaluated_cscids_cnt += 1;
					next;
				}
			}

			my $csc_obj = CertReader::App::EvalCrosssign::CrosssignCert->new(
				db => $self->db,
				tablepostfix => $self->tablepostfix,
				subject => $csc->subject,
				csc_id => $csc->id,
				rootstore_cache => $self->{'rootstore_cache'},
				worker_prefix => $prefix,
			);
			my $current_cscid_starttime = time;

			# Get certificates for this cross-sign candidate; There should not be too much, hence we do not batch
			my $csc_cert_iterator = CertReader::DB::CrossSignCandidateCert::Manager->get_csc_certs_iterator_for_csc($self->db, $self->tablepostfix, $csc);
			while (my $csc_cert = $csc_cert_iterator->next) {
				next if $csc_cert->from_subj_alt_ext and !$self->with_san_lists;

				my $cert = $csc_cert->cert;
				if ($self->ignore_invalid) {
					if (!$cert->is_valid($self->tablepostfix)) {
						next;
					}
				}

				$csc_obj->add_cert($cert, $cert->subject);

			}


			if ($csc_obj->is_cs) {

				unless (defined $w_log_cscerts_fh) {
					$w_log_cscerts_fh = FileHandle->new($w_log_cscerts, '>:encoding(UTF-8)');
					croak("Could not open $w_log_cscerts") if !defined($w_log_cscerts_fh);
					$w_log_cscerts_fh->autoflush(1);
				}
				unless (defined $w_log_subgroup_cscerts_fh) {
					$w_log_subgroup_cscerts_fh = FileHandle->new($w_log_subgroup_cscerts, '>:encoding(UTF-8)');
					croak("Could not open $w_log_subgroup_cscerts") if !defined($w_log_subgroup_cscerts_fh);
					$w_log_subgroup_cscerts_fh->autoflush(1);
				}
				unless (defined $w_log_evalrootstore_fh) {
					$w_log_evalrootstore_fh = FileHandle->new($w_log_evalrootstore, '>:encoding(UTF-8)');
					croak("Could not open $w_log_evalrootstore") if !defined($w_log_evalrootstore_fh);
					$w_log_evalrootstore_fh->autoflush(1);
				}

				my $w_cscerts = [];
				push(@{$w_cscerts}, $csc_obj);

				my $csc_metadata = CertReader::DB::CrossSignCandidateMetaData->new(csc_id => $csc->id);
				$csc_metadata->load(speculative => 1);
				$csc_metadata->evaluated_at(time2str("%Y-%m-%d %H:%M:%S", $current_cscid_starttime, "UTC"));
				my $write_to_db = 1;
				my $csc_metadata_str = $csc_obj->get_metadata($csc_metadata, $write_to_db);
				# Note: $csc_metadata_str gets written to $w_log_cscerts_fh below
				$time_csccerts //= 0;
				$time_csccerts += (time - $time_start);

				$time_start = time;
				# Now look for subgroups in cross-signing (considering that not all
				# validity periods of the certificates in a cross-sign cert overlap)
				my $w_subgroup_cscerts = [];
				for my $subgroup_cs_cert (@{$csc_obj->get_subgroups_as_cscerts}) {
					push(@{$w_subgroup_cscerts}, $subgroup_cs_cert);
					my $write_to_db = 0;
					say $w_log_subgroup_cscerts_fh join "\n", map {"Subgroup: " . $_} split("\n", $subgroup_cs_cert->get_metadata(undef, $write_to_db));
					say $w_log_subgroup_cscerts_fh "";
				}
				$time_subgroup_cscerts //= 0;
				$time_subgroup_cscerts += (time - $time_start);

				my $w_stats = {};
				if ($self->gather_stats) {
					$time_start = time;
					$self->populate_stats($w_stats, $w_cscerts, '[all-in-one-cscert] ');
					$self->populate_stats($w_stats, $w_subgroup_cscerts, '[subgroups] ');
					$time_populate_stats //= 0;
					$time_populate_stats += (time - $time_start);
				}

				if ($self->legacy_rootstore_eval) {
					$time_start = time;
					$self->eval_rootstores($w_stats, $w_cscerts, $w_log_evalrootstore_fh);

					# eval_rootstores currently does not support different cscert groups for
					# the same stats hash (would overwrite/squash-in results)
					# $self->eval_rootstores($w_stats, $w_subgroup_cscerts);  # TODO needed?

					$time_eval_rootstores //= 0;
					$time_eval_rootstores += (time - $time_start);
				}

				if ($self->with_aki_ext_eval) {
					$time_start = time;
					# TODO provide logfile for output
					$self->eval_extension_authority_key_identifier($w_cscerts, $w_stats);
					# eval_extension_authority_key_identifier currently does not support
					# different cscert groups for the same stats hash (would overwrite/
					# squash-in results)
					# TODO provide logfile for output
					# $self->eval_extension_authority_key_identifier($w_subgroup_cscerts, $w_stats);  # TODO
					$time_eval_extension_authority_key_identifier //= 0;
					$time_eval_extension_authority_key_identifier += (time - $time_start);
				}

				merge_stats($w_stats_overall, $w_stats);

				# write to output file just before updating eval-state in DB to minimize inconsistencies
				say $w_log_cscerts_fh $csc_metadata_str;
			}

			$csc_evalstate->evaluated_at(time2str("%Y-%m-%d %H:%M:%S", $current_cscid_starttime, "UTC"));
			$csc_evalstate->save;

		}
		undef $w_log_cscerts_fh;  # automatically closes the file
		undef $w_log_subgroup_cscerts_fh;  # automatically closes the file
		undef $w_log_evalrootstore_fh;  # automatically closes the file

		$time_csccerts = "skipped" if (not defined($time_csccerts));
		$time_subgroup_cscerts = "skipped" if (not defined($time_subgroup_cscerts));
		$time_populate_stats = "skipped" if (not defined($time_populate_stats));
		$time_eval_rootstores = "skipped" if (not defined($time_eval_rootstores));
		$time_eval_extension_authority_key_identifier = "skipped" if (not defined($time_eval_extension_authority_key_identifier));
		my $timeinfo_str = "";
		$timeinfo_str .= "\t" . localtime() . "    $prefix\t cscerts:  $time_csccerts sec" if $self->verbosity > 0;
		$timeinfo_str .= "\n\t" . localtime() . "    $prefix\t subgroup_cscerts:  $time_subgroup_cscerts sec" if $self->verbosity > 0;
		$timeinfo_str .= "\n\t" . localtime() . "    $prefix\t populate_stats:  $time_populate_stats sec" if $self->verbosity > 0;
		$timeinfo_str .= "\n\t" . localtime() . "    $prefix\t eval_rootstores:  $time_eval_rootstores sec" if $self->verbosity > 0;
		$timeinfo_str .= "\n\t" . localtime() . "    $prefix\t eval_extension_authority_key_identifier:  $time_eval_extension_authority_key_identifier sec" if $self->verbosity > 0;
		say $timeinfo_str if $self->verbosity > 0;
		if ($skipped_already_evaluated_cscids_cnt) {
			say "\t" . localtime() . "    $prefix  Skipped $skipped_already_evaluated_cscids_cnt csc_ids as already evaluated (batch $currid_start_backup - $lastid)";
		}

	}

	say "$prefix finished.";
	return 0, $w_stats_overall;
}

sub merge_stats {
	my ($stats_overall, $stats_sub) = @_;

	for my $key (keys %{$stats_sub}) {
		my $key_defined = exists($stats_overall->{$key});
		my $value = $stats_sub->{$key};
		if (ref($value) eq "HASH") {
			$stats_overall->{$key} = {} if !$key_defined;
			merge_stats($stats_overall->{$key}, $value);
		} elsif (ref($value) eq "ARRAY") {
			$stats_overall->{$key} = [] if !$key_defined;
			for my $array_entry (@$value) {
				push(@{$stats_overall->{$key}}, $array_entry);
			}
		} elsif (ref($value) eq "") {
			# It is not a reference
			# TODO does that really always mean that it is an scalar?
			$stats_overall->{$key} = 0 if !$key_defined;
			$stats_overall->{$key} += $value;
		} else {
			croak("merge_stats: Merging for reference to type " . ref($value) . " not implemented!");
		}
	}
}

sub populate_stats {
	my ($self, $stats, $cs_certs, $prefix) = @_;

	# say "Starting statistical analysis ($prefix)...";
	my $cs_certs_cnt = scalar @{$cs_certs};
	my $cs_certs_cnt_valid = 0;
	my $cs_rootcert_cnt = 0;
	my $cs_intermediate_cnt = 0;
	my $cs_leaf_cnt = 0;
	my $cs_leafmix_cnt = 0;

	my $cs_ca_intern_singlecert_cnt = 0;
	my $cs_ca_intern_multicert_cnt = 0;
	my $cs_ca_intern_multicert_oneCA_cnt = 0;
	my $cs_ca_intern_multiCAs_cnt = 0;
	my $cs_ca_extern_singlecert_cnt = 0;
	my $cs_ca_extern_multicert_cnt = 0;
	my $cs_ca_extern_multicert_oneCA_cnt = 0;
	my $cs_ca_extern_multiCAs_cnt = 0;
	my $cs_leaf_singleCA_cnt = 0;
	my $cs_leaf_multiCAs_cnt = 0;
	my $cs_leaf_singlecert_oneCA_cnt = 0;
	my $cs_leaf_multicert_oneCA_cnt = 0;

	$stats->{$prefix . 'cert_distribution_all'} = {};
	$stats->{$prefix . 'cert_distribution_valid'} = {};
	$stats->{$prefix . 'cert_distribution_valid_and_cs_valid'} = {};
	$stats->{$prefix . 'issuer_distribution_all'} = {};
	$stats->{$prefix . 'issuer_distribution_valid'} = {};
	$stats->{$prefix . 'issuer_distribution_valid_and_cs_valid'} = {};

	$stats->{$prefix . 'issuer_groups'} = {};

	my $rootstore_categories_cnt = get_rootstore_categories_cnt();
	say {$self->{fh_log}} "We consider $rootstore_categories_cnt different rootstore categories";
	for (my $i = 1; $i <= $rootstore_categories_cnt; $i++) {
		$stats->{$prefix . 'rootstore_coverage - ' . sprintf("%02d", $i) . ' rootstore(s)'} = {};
	}


	foreach (@{$cs_certs}) {
		$cs_certs_cnt_valid += 1 if $_->is_cs_valid;

		$cs_rootcert_cnt += 1 if $_->is_cs_rootcert;
		$cs_intermediate_cnt += 1 if $_->is_cs_intermediate;
		$cs_leaf_cnt += 1 if $_->is_cs_leaf;
		$cs_leafmix_cnt += 1 if $_->is_cs_leafmix;

		$cs_ca_intern_singlecert_cnt += 1 if $_->is_cs_ca_intern_singlecert;
		$cs_ca_intern_multicert_cnt += 1 if $_->is_cs_ca_intern_multicert;
		$cs_ca_intern_multicert_oneCA_cnt += 1 if $_->is_cs_ca_intern_multicert_oneCA;
		$cs_ca_intern_multiCAs_cnt += 1 if $_->is_cs_ca_intern_multiCAs;
		$cs_ca_extern_singlecert_cnt += 1 if $_->is_cs_ca_extern_singlecert;
		$cs_ca_extern_multicert_cnt += 1 if $_->is_cs_ca_extern_multicert;
		$cs_ca_extern_multicert_oneCA_cnt += 1 if $_->is_cs_ca_extern_multicert_oneCA;
		$cs_ca_extern_multiCAs_cnt += 1 if $_->is_cs_ca_extern_multiCAs;
		$cs_leaf_singleCA_cnt += 1 if $_->is_cs_leaf_singleCA;
		$cs_leaf_multiCAs_cnt += 1 if $_->is_cs_leaf_multiCAs;
		$cs_leaf_singlecert_oneCA_cnt += 1 if $_->is_cs_leaf_singlecert_oneCA;
		$cs_leaf_multicert_oneCA_cnt += 1 if $_->is_cs_leaf_multicert_oneCA;

		my @distribution_values = (
			[$prefix . 'cert_distribution_all', $_->get_cert_cnt],
			[$prefix . 'cert_distribution_valid', $_->get_cert_cnt_valid],
			[$prefix . 'issuer_distribution_all', $_->get_issuer_cnt],
			[$prefix . 'issuer_distribution_valid', $_->get_issuer_cnt_valid],
		);
		if ($_->is_cs_valid) {
			push(@distribution_values, [$prefix . 'cert_distribution_valid_and_cs_valid', $_->get_cert_cnt_valid]);
			push(@distribution_values, [$prefix . 'issuer_distribution_valid_and_cs_valid', $_->get_issuer_cnt_valid]);
		}
		for my $kv (@distribution_values) {
			my ($key, $value) = @$kv;
			if (!defined( $stats->{$key}->{$value})) {
				$stats->{$key}->{$value} = 0;
			}
			$stats->{$key}->{$value} += 1;
		}

		my $issuer_group = "\n" . (join "\n", @{$_->get_issuers_sorted}) . "\n";
		if (!defined $stats->{$prefix . 'issuer_groups'}->{$issuer_group}) {
			$stats->{$prefix . 'issuer_groups'}->{$issuer_group} = 0;
		}
		$stats->{$prefix . 'issuer_groups'}->{$issuer_group} += 1;

		# Calculate how many rootstores are covered when selectively adding
		# the issuers (always preferring the issuer with the largest impact on
		# the number of trusted rootstores)
		#
		# TODO Do we really want to start with the root-cert that covers the largest
		# number of truststores? I think it would make more sense to start with the
		# root-certificate of the "natural" issuer, i.e., the root certificate of
		# the issuer that also owns the intermediate certificate. Not that easy to
		# automate, though.
		my $stli = $_->get_storelabels_by_issuer($self->{fh_log});
		my $trusted_stores = {};
		my @issuers_considered;
		my $largest_impact = 0;
		my $issuer_largest_impact = '';
		say {$self->{fh_log}} "calculating rootstore coverage of certificate" if $self->debug_rootstore_coverage;
		while (scalar keys %$stli > 0) {
			if ($self->debug_rootstore_coverage) {
				say {$self->{fh_log}} "\tnew round";
				say {$self->{fh_log}} "\t\tconsidered issuers: " . scalar @issuers_considered;
				say {$self->{fh_log}} "\t\tremaining issuers: " . scalar keys %$stli;
			}
			for my $curr_issuer (keys %$stli) {
				# Get rootstore categories for issuer
				# if (scalar @{$stli->{$curr_issuer}} == 0) {
				# 	# warn "WARN: Skipping issuer without trusted path";
				# 	next;
				# }
				my $categories = {};
				for my $label (@{$stli->{$curr_issuer}}) {
					$categories->{ label_to_category($label) } = 1;
				}

				# Now calculate the impact
				my $curr_issuer_impact = 0;
				for my $category (keys %$categories) {
					if (! defined $trusted_stores->{$category}) {
						$curr_issuer_impact += 1;
					}
				}
				say {$self->{fh_log}} "\t\t\t$curr_issuer has impact $curr_issuer_impact" if $self->debug_rootstore_coverage;

				if ($curr_issuer_impact > $largest_impact or $issuer_largest_impact eq '') {
					$issuer_largest_impact = $curr_issuer;
					$largest_impact = $curr_issuer_impact;
				}
			}

			say {$self->{fh_log}} "\t\t\tSelected $issuer_largest_impact (impact $largest_impact)" if $self->debug_rootstore_coverage;
			my $stores_covered_before = scalar keys %$trusted_stores;
			for my $label (@{$stli->{$issuer_largest_impact}}) {
				$trusted_stores->{ label_to_category($label) } = 1;
			}
			my $stores_covered_now = scalar keys %$trusted_stores;
			push @issuers_considered, $issuer_largest_impact;
			delete $stli->{$issuer_largest_impact};
			# Update statistics
			for (my $i = $stores_covered_before + 1; $i <= $stores_covered_now; $i++) {
				if (! defined $stats->{$prefix . 'rootstore_coverage - ' . sprintf("%02d", $i) . ' rootstore(s)'}->{scalar @issuers_considered}) {
					$stats->{$prefix . 'rootstore_coverage - ' . sprintf("%02d", $i) . ' rootstore(s)'}->{scalar @issuers_considered} = 0;
				}
				say {$self->{fh_log}} "Incrementing rootstore_coverage - $i rootstore" if $self->debug_rootstore_coverage;
				$stats->{$prefix . 'rootstore_coverage - ' . sprintf("%02d", $i) . ' rootstore(s)'}->{scalar @issuers_considered} += 1;
			}

			$issuer_largest_impact = '';
			$largest_impact = 0;
		}


	}
	my $stats_label = $prefix . "Number of cross-sign certificates";
	if ($self->with_san_lists) {
		$stats_label .= " _with_SAN_";
	}
	say {$self->{fh_log}} "Found $cs_certs_cnt $stats_label (thereof $cs_certs_cnt_valid are valid crosssign certs)";
	$stats->{$stats_label} = $cs_certs_cnt;
	$stats->{$stats_label . " (valid cross-sign)"} = $cs_certs_cnt_valid;

	$stats->{$prefix . 'category cs_rootcert'} = $cs_rootcert_cnt;
	$stats->{$prefix . 'category cs_intermediate'} = $cs_intermediate_cnt;
	$stats->{$prefix . 'category cs_leaf'} = $cs_leaf_cnt;
	$stats->{$prefix . 'category cs_leafmix'} = $cs_leafmix_cnt;

	$stats->{$prefix . 'category_owner cs_ca_intern_singlecert'} = $cs_ca_intern_singlecert_cnt;
	$stats->{$prefix . 'category_owner cs_ca_intern_multicert'} = $cs_ca_intern_multicert_cnt;
	$stats->{$prefix . 'category_owner cs_ca_intern_multicert_oneCA'} = $cs_ca_intern_multicert_oneCA_cnt;
	$stats->{$prefix . 'category_owner cs_ca_intern_multiCAs'} = $cs_ca_intern_multiCAs_cnt;
	$stats->{$prefix . 'category_owner cs_ca_extern_singlecert'} = $cs_ca_extern_singlecert_cnt;
	$stats->{$prefix . 'category_owner cs_ca_extern_multicert'} = $cs_ca_extern_multicert_cnt;
	$stats->{$prefix . 'category_owner cs_ca_extern_multicert_oneCA'} = $cs_ca_extern_multicert_oneCA_cnt;
	$stats->{$prefix . 'category_owner cs_ca_extern_multiCAs'} = $cs_ca_extern_multiCAs_cnt;
	$stats->{$prefix . 'category_owner cs_leaf_singleCA'} = $cs_leaf_singleCA_cnt;
	$stats->{$prefix . 'category_owner cs_leaf_multiCAs'} = $cs_leaf_multiCAs_cnt;
	$stats->{$prefix . 'category_owner cs_leaf_singlecert_oneCA'} = $cs_leaf_multicert_oneCA_cnt;
	$stats->{$prefix . 'category_owner cs_leaf_multicert_oneCA'} = $cs_leaf_multicert_oneCA_cnt;
}

sub eval_rootstores {
	my ($self, $stats, $cs_certs, $fh_log) = @_;
	my $postfix = $self->tablepostfix;

	my $stats_label = "Cross-sign certs with distinct rootstore categories for issuers";
	$stats->{$stats_label} = 0;

	for my $cs_cert (@$cs_certs) {
		my $stli = $cs_cert->get_storelabels_by_issuer($self->{fh_log});
		my $stats_label_percs = "\tdistinct root store categories for " . $cs_cert->readable_id;
		my $distinct_any = 0;

		my $categories_per_issuer = {};
		for my $curr_issuer (sort keys %$stli) {
			# Get rootstore categories for issuer
			if (scalar @{$stli->{$curr_issuer}} == 0) {
				say {$self->{fh_log}} "WARNING: Skipping issuer without trusted path";
				next;
			}
			my $categories = {};
			for my $label (@{$stli->{$curr_issuer}}) {
				$categories->{ label_to_category($label) } = 1;
			}

			# compare with categories of already processed issuers (i.e.,
			# compare each issuer pair exactly once)
			for my $issuer (sort keys %$categories_per_issuer) {
				my @distinct;
				foreach(sort keys %{$categories_per_issuer->{$issuer}}) {
					push(@distinct, $_) if !defined($categories->{$_});
				}
				foreach(sort keys %$categories) {
					push(@distinct, $_) if !defined($categories_per_issuer->{$issuer}->{$_});
				}
				if (scalar @distinct) {
					$distinct_any = 1;

					$stats->{$stats_label_percs} += 1;
					say $fh_log "--- Result ---";
					say $fh_log "Found distinct rootstore categories";
					print $fh_log join "\n", map {"CS-cert: " . $_} split("\n", "$cs_cert");
					print $fh_log "distinct categories: " . Dumper(\@distinct);
					print $fh_log "labels issuer 1 ($curr_issuer): " . Dumper($stli->{$curr_issuer});
					print $fh_log "labels issuer 2 ($issuer): " . Dumper($stli->{$issuer});
					say $fh_log "--------------";
				}
			}

			# store info of current issuer for next loop
			$categories_per_issuer->{$curr_issuer} = $categories;
		}
		$stats->{$stats_label} += 1 if $distinct_any;
	}

}

sub eval_extension_authority_key_identifier {
	my ($self, $cs_certs, $stats) = @_;
	my $postfix = $self->tablepostfix;

	# TODO extract the interesting facts to $stats
	for my $cs_cert (@$cs_certs) {

		my $results_str = $cs_cert->readable_id;
		my $ski_missing = 0;
		my $skis_differ = 0;
		my $akis_differ = 0;
		my $aki_hasSerial = 0;
		my $aki_unexpected_akiSkiMismatch = 0;
		my $aki_unexpected_subject = 0;
		my $aki_unexpected_serial = 0;

		my $parse_warning = 0;

		my $akis = {};
		my $serials = {};
		my $skis = {};

		for my $cert (@{$cs_cert->get_certs}) {
			my $certid = $cert->id;

			my $exts = CertReader::DB::CertificateExtension::Manager->get_certificateextensions_from_sql(
				db => $self->db,
				inject_results => 1,
				sql => "select * from certificate_extension_full where certificate_id = $certid and name = 'subjectKeyIdentifier' order by id;",
			);
			for my $ext (@$exts) {
				my $value = $ext->value;
				$skis->{$value} = 1;
				chomp($value);
				$results_str .= "\n" . $cert->id . ":    \t(ski): " . $value . "\tserial: " . $cert->serial;
				$serials->{$cert->serial} = 1;
			}
			if ((scalar @$exts) == 0) {
				$ski_missing = 1;
				$results_str .= "\n" . $cert->id . ":    \t(ski): " . "WARNING No ski" . "\tserial: " . $cert->serial;
			}
		}

		$skis_differ = 1 if scalar keys %$skis > 1;

		my $cs_cert_subject = $cs_cert->subject;
		my $cs_cert_subject_escaped = $self->db->dbh->quote($cs_cert_subject);
		my $clientcert_exts = CertReader::DB::CertificateExtension::Manager->get_certificateextensions_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => "select * from certificate_extension_$postfix where certificate_id in (select id from certificate_full where issuer = $cs_cert_subject_escaped) and name = 'authorityKeyIdentifier' order by id;",
		);
		for my $cc_ext (@$clientcert_exts) {

			if ($self->ignore_invalid) {
				if (!$self->is_certid_valid($cc_ext->certificate_id)) {
					next;
				}
			}

			my $calculate_if_valid = 0;
			my $value = $cc_ext->value;
			$akis->{$value} = 1;
			my $flags = "";

			# TODO a serial number references a specific certificate, validation may screw up here --> check validation paths
			$aki_hasSerial = 1 if $value =~ /serial/;

			# TODO Check if the ski matches any of the aki's
			for my $aki_line (split /\n/, $value) {
				if ($aki_line =~ /keyid:/) {
					my $aki_keyid = $aki_line;
					$aki_keyid =~ s/\Akeyid://;
					if (!$skis->{$aki_keyid}) {
						$aki_unexpected_akiSkiMismatch = 1;
						$calculate_if_valid = 1;
						$flags .= ",akiSkiMismatch";
					}
					# say $aki_keyid; # DEBUG
				}
				elsif ($aki_line =~ /DirName:/) {
					my $aki_dirname = $aki_line;
					$aki_dirname =~ s/\ADirName://;
					$aki_dirname =~ s/\A\///g;
					$aki_dirname =~ s/\//, /g; # TODO this has problems if the actual text in the subject includes /
					if (!($aki_dirname eq $cs_cert_subject)) {
						$aki_unexpected_subject = 1;
						$calculate_if_valid = 1;
						$flags .= ",akiSubjectMismatch";
					}
					# say $aki_dirname; # DEBUG
				}
				elsif ($aki_line =~ /serial:/) {
					$calculate_if_valid = 1; # interesting if our evaluation considers serial or not

					my $aki_serial = $aki_line;
					$aki_serial =~ s/\Aserial://;
					$aki_serial =~ s/://g;
					if (!$serials->{$aki_serial}) {
						$aki_unexpected_serial = 1;
						$flags .= ",akiSerialMismatch";
					}
					# say $aki_serial; # DEBUG
				} else {
					warn "WARNING: Unknown ski format: $aki_line";
					$parse_warning = 1;
				}
			}
			# $ski_unexpected = 1 if ...

			my $valid = "n/a";
			if ($calculate_if_valid) {
				my $vts = CertReader::DB::VerifyTree::Manager->get_verifypaths_from_sql(
					db => $self->db,
					inject_results => 1,
					sql => "select * from verify_tree_$postfix where certificate = " . $cc_ext->certificate_id . " LIMIT 1;",
				);
				if (scalar @$vts) {
					$valid = "true"
				} else {
					$valid = "false"
				}
			}

			chomp($value);
			$value =~ s/\n/ /g;
			$results_str .= "\n" . "\t" . $cc_ext->certificate_id . ": \t(aki): " . $value . " \t valid: $valid";
			$results_str .= "\t flags: $flags" if !($flags eq "")
		}
		$results_str .= "\n" . "-----\n";

		$akis_differ = 1 if scalar keys %$akis > 1;

		if ($parse_warning or
			$ski_missing or
			$skis_differ or
			$akis_differ or
			$aki_hasSerial or
			$aki_unexpected_akiSkiMismatch or
			$aki_unexpected_subject or
			$aki_unexpected_serial)
		{
			say "parse_warning: $parse_warning";
			say "ski_missing: $ski_missing";
			say "skis_differ: $skis_differ";
			say "akis_differ: $akis_differ";
			say "aki_hasSerial: $aki_hasSerial";
			say "aki_unexpected_akiSkiMismatch: $aki_unexpected_akiSkiMismatch";
			say "aki_unexpected_subject: $aki_unexpected_subject";
			say "aki_unexpected_serial: $aki_unexpected_serial";

			say $results_str;
		}
	}

}

package CertReader::App::EvalCrosssign::CrosssignCert;

use 5.14.1;
use strict;
use warnings;

use Carp;
use Moose;
use Data::Dumper;
use Time::Piece;
use Date::Format qw[time2str];
use List::Util qw[min max];

has 'csc_id' => ( # equals cross_sign_candidate_full(id) and csc_cert_full(csc_id)
	is => 'ro',
	isa => 'Int',
	required => 1,
);

has '_certs' => (
	accessor => 'certs',
	is => 'rw',
	isa => 'HashRef',
	required => 0,
	default => sub { {} },
);

has '_crosssign_minimum_overlap_days' => (
	is => 'ro',
	isa => 'Int',
	required => 1,
	default => 121,
);

has 'is_subgroup_cscert' => (
	is => 'ro',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'If true, this cscert has been created from a validity subgroup, i.e., all certificates have a total validity period overlap or at least _crosssign_minimum_overlap_days',
);

has 'db' => (
	is => 'rw',
	isa => 'CertReader::DB',
	required => 1,
);

has 'tablepostfix' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
);

has 'subject' => (
	is => 'ro',
	isa => 'Str',
	required => 1,
);

has 'rootstore_cache' => (
	is => 'ro',
	isa => 'HashRef',
	required => 1,
);

has 'worker_prefix' => (
	is => 'rw',
	isa => 'Str',
	required => 0,
);

	use overload fallback => 1,
		'""' => sub {
			my $self = shift;
			return "XS-cert $self->{csc_id}";
		};

sub get_metadata {
			my ($self, $csc_metadata, $write_to_db) = @_;
			$write_to_db //= 0;

			my $ret = "";
			$ret .= "Subgroup-" if $self->is_subgroup_cscert;
			$ret .= "CrossSignCert(\n";
			my $csc_id = $self->csc_id;
			$ret .= "\tcsc_id: $csc_id\n";
			my $cs_any_cert_valid = $self->is_any_cert_valid;
			my $cs_valid = $self->is_cs_valid;
			my $cs_withroot = $self->has_rootcert;
			my $cs_withrevokedroot = $self->has_revokedcert;
			$ret .= "\tany_cert_valid: $cs_any_cert_valid, cs_valid: $cs_valid, with_root: $cs_withroot, with_revoked_root: $cs_withrevokedroot\n";
			$csc_metadata->any_cert_valid($cs_any_cert_valid) if defined($csc_metadata);
			$csc_metadata->cs_valid($cs_valid) if defined($csc_metadata);
			$csc_metadata->with_root($cs_withroot) if defined($csc_metadata);
			$csc_metadata->with_revoked_root($cs_withrevokedroot) if defined($csc_metadata);
			# results of _classify
			$ret .= "\tcs_rootcert: " . $self->is_cs_rootcert;
			$csc_metadata->cs_rootcert($self->is_cs_rootcert) if defined($csc_metadata);
			$ret .= ", cs_intermediate: " . $self->is_cs_intermediate;
			$csc_metadata->cs_intermediate($self->is_cs_intermediate) if defined($csc_metadata);
			$ret .= ", cs_leaf: " . $self->is_cs_leaf;
			$csc_metadata->cs_leaf($self->is_cs_leaf) if defined($csc_metadata);
			$ret .= ", cs_leafmix: " . $self->is_cs_leafmix;
			$csc_metadata->cs_leafmix($self->is_cs_leafmix) if defined($csc_metadata);
			$ret .= ", cs_multiSignAlgs: " . $self->is_cs_multiSignAlgs;
			$csc_metadata->cs_multisignalgs($self->is_cs_multiSignAlgs) if defined($csc_metadata);
			$ret .= ", cs_expandingStores: " . $self->is_cs_expandingStores;
			$csc_metadata->cs_expanding_store($self->is_cs_expandingStores) if defined($csc_metadata);
			$ret .= ", cs_expandingTime: " . $self->is_cs_expandingTime;
			$csc_metadata->cs_expanding_time($self->is_cs_expandingTime) if defined($csc_metadata);
			$ret .= ", cs_alternPaths: " . $self->is_cs_alternPaths;
			$csc_metadata->cs_alternpaths($self->is_cs_alternPaths) if defined($csc_metadata);
			$ret .= ", cs_bootstrapping: " . $self->is_cs_bootstrapping;
			$csc_metadata->cs_bootstrapping($self->is_cs_bootstrapping) if defined($csc_metadata);
			$ret .= "\n";

			$ret .= "\tcs_ca_intern_singlecert: " . $self->is_cs_ca_intern_singlecert;
			$csc_metadata->cs_ca_intern_singlecert($self->is_cs_ca_intern_singlecert) if defined($csc_metadata);
			$ret .= ", cs_ca_intern_multicert: " . $self->is_cs_ca_intern_multicert;
			$csc_metadata->cs_ca_intern_multicert($self->is_cs_ca_intern_multicert) if defined($csc_metadata);
			$ret .= ", cs_ca_intern_multicert_oneCA: " . $self->is_cs_ca_intern_multicert_oneCA;
			$csc_metadata->cs_ca_intern_multicert_oneca($self->is_cs_ca_intern_multicert_oneCA) if defined($csc_metadata);
			$ret .= ", cs_ca_intern_multiCAs: " . $self->is_cs_ca_intern_multiCAs;
			$csc_metadata->cs_ca_intern_multicas($self->is_cs_ca_intern_multiCAs) if defined($csc_metadata);
			$ret .= "\n";
			$ret .= "\tcs_ca_extern_singlecert: " . $self->is_cs_ca_extern_singlecert;
			$csc_metadata->cs_ca_extern_singlecert($self->is_cs_ca_extern_singlecert) if defined($csc_metadata);
			$ret .= ", cs_ca_extern_multicert: " . $self->is_cs_ca_extern_multicert;
			$csc_metadata->cs_ca_extern_multicert($self->is_cs_ca_extern_multicert) if defined($csc_metadata);
			$ret .= ", cs_ca_extern_multicert_oneCA: " . $self->is_cs_ca_extern_multicert_oneCA;
			$csc_metadata->cs_ca_extern_multicert_oneca($self->is_cs_ca_extern_multicert_oneCA) if defined($csc_metadata);
			$ret .= ", cs_ca_extern_multiCAs: " . $self->is_cs_ca_extern_multiCAs;
			$csc_metadata->cs_ca_extern_multicas($self->is_cs_ca_extern_multiCAs) if defined($csc_metadata);
			$ret .= "\n";
			$ret .= "\tcs_leaf_singleCA: " . $self->is_cs_leaf_singleCA;
			$csc_metadata->cs_leaf_singleca($self->is_cs_leaf_singleCA) if defined($csc_metadata);
			$ret .= ", cs_leaf_multiCAs: " . $self->is_cs_leaf_multiCAs;
			$csc_metadata->cs_leaf_multicas($self->is_cs_leaf_multiCAs) if defined($csc_metadata);
			$ret .= ", cs_leaf_singlecert_oneCA: " . $self->is_cs_leaf_singlecert_oneCA;
			$csc_metadata->cs_leaf_singlecert_oneca($self->is_cs_leaf_singlecert_oneCA) if defined($csc_metadata);
			$ret .= ", cs_leaf_multicert_oneCA: " . $self->is_cs_leaf_multicert_oneCA;
			$csc_metadata->cs_leaf_multicert_oneca($self->is_cs_leaf_multicert_oneCA) if defined($csc_metadata);
			$ret .= "\n";

			$ret .= "\tvalidity_gap: " . $self->has_validity_gap;
			$csc_metadata->validity_gap($self->has_validity_gap) if defined($csc_metadata);
			$ret .= ", sub_groups: " . ($self->is_subgroup_cscert ? "n/a" : scalar @{$self->get_certs_by_validity_subgroups});
			$csc_metadata->sub_groups(($self->is_subgroup_cscert ? undef : scalar @{$self->get_certs_by_validity_subgroups})) if defined($csc_metadata);
			my $largest_validcertcnt_subgroups = "n/a";
			my $largest_validcertcnt_subgroups_db;
			my $string_subgroups = "";
			if ($self->is_subgroup_cscert != 1) {

				$largest_validcertcnt_subgroups = 0;

				my $certs_by_validity_subgroups = $self->get_certs_by_validity_subgroups;
				$string_subgroups .= "\tSubgroups: " . (scalar @$certs_by_validity_subgroups) . "\n";
				my $subgroup_cnt = 1;
				for my $subgroup (@$certs_by_validity_subgroups) {
					my $subgroup_valid_cert_cnt = 0;
					# my $subgroup_notbefore = (@$subgroup[0])->not_before;
					# my $subgroup_notafter = (@$subgroup[-1])->not_after;
					# $string_subgroups .= "\t\tSubgroup $subgroup_cnt ($subgroup_notbefore - $subgroup_notafter): ";
					$string_subgroups .= "\t\tSubgroup $subgroup_cnt: ";
					for my $cert (@$subgroup) {
						if ($cert->is_valid($self->tablepostfix)) {
							$string_subgroups .= $cert->id . ",";
							$subgroup_valid_cert_cnt += 1;
						}
					}
					$string_subgroups .= "\n";
					$subgroup_cnt += 1;
					$largest_validcertcnt_subgroups = max($subgroup_valid_cert_cnt, $largest_validcertcnt_subgroups);
					$largest_validcertcnt_subgroups_db = $largest_validcertcnt_subgroups;
				}
			}
			$ret .= ", largest_validcertcnt_subgroups: " . $largest_validcertcnt_subgroups;
			$csc_metadata->largest_validcertcnt_subgroups($largest_validcertcnt_subgroups_db) if defined($csc_metadata);
			$ret .= "\n";
			$ret .= "\tSubject/SAN entry: " . $self->subject() . "\n";

			my $owners_all_issuers = join("; ", sort @{$self->get_owners_all_issuers});
			my $owners_all_certs = join("; ", sort @{$self->get_owners_all_certs});
			$ret .= "\towners_issuers: " . $owners_all_issuers . "\n";
			$ret .= "\towners_certs:   " . $owners_all_certs . "\n";
			$ret .= "\ttex_command: \\xs\{$owners_all_issuers\}\{$owners_all_certs\}\{$csc_id\}\n";

			if ($self->is_subgroup_cscert != 1) {
				$ret .= $string_subgroups;
			}

			my $sig_algo_to_id = {};
			my $key_algo_to_id = {};
			my $issuer_cnt = 1;
			for my $issuer (sort keys %{$self->certs}) {
				$ret .= "\tIssuer $issuer_cnt: $issuer\n";
				my $issuer_ids = $self->get_issuerids_for_issuer($issuer);
				$ret .= "\t\tissuer_certs     : " . join(",", sort @$issuer_ids) . "\n";
				my $issuer_sig_algo_ids = [];
				my $issuer_key_algo_ids = [];
				my $issuer_is_root = [];
				my $issuer_validity_periods = [];
				for my $issuer_id (sort @$issuer_ids) {
					my $issuer_cert = CertReader::DB::Certificate->new(id => $issuer_id);
					$issuer_cert->load();
					$sig_algo_to_id->{$issuer_cert->sig_algo} //= (scalar (keys %$sig_algo_to_id));
					push @$issuer_sig_algo_ids, $sig_algo_to_id->{$issuer_cert->sig_algo};
					$key_algo_to_id->{$issuer_cert->key_algo} //= (scalar (keys %$key_algo_to_id));
					push @$issuer_key_algo_ids, $key_algo_to_id->{$issuer_cert->key_algo};
					push @$issuer_is_root, $issuer_cert->is_root_cert;
					push @$issuer_validity_periods, $issuer_cert->not_before . " - " . $issuer_cert->not_after . " (" . $issuer_cert->id . ")";
				}
				my $sig_algo_id_mapping = [];
				for my $sig_algo_cur (sort { $sig_algo_to_id->{$a} <=> $sig_algo_to_id->{$b} } keys %$sig_algo_to_id) {
					push @$sig_algo_id_mapping, $sig_algo_to_id->{$sig_algo_cur} . ": $sig_algo_cur";
				}
				my $key_algo_id_mapping = [];
				for my $key_algo_cur (sort { $key_algo_to_id->{$a} <=> $key_algo_to_id->{$b} } keys %$key_algo_to_id) {
					push @$key_algo_id_mapping, $key_algo_to_id->{$key_algo_cur} . ": $key_algo_cur";
				}
				$ret .= "\t\tissuer_is_root   : " . join("", @$issuer_is_root) . "\n";
				$ret .= "\t\tissuer_sig_algo  : " . join("", @$issuer_sig_algo_ids) . "  (" . join(", ", @$sig_algo_id_mapping) . ")\n";
				$ret .= "\t\tissuer_key_algo  : " . join("", @$issuer_key_algo_ids) . "  (" . join(", ", @$key_algo_id_mapping) . ")\n";
				$ret .= "\t\tissuer_validities: " . join("\n\t\t                   ", @$issuer_validity_periods) . "\n";
				my $issuer_owner_cnt = 1;
				for my $notbefore (sort keys %{$self->get_owner_chains_by_validitydate_for_issuer($issuer)}) {
					for my $owner_chain (@{$self->get_owner_chains_by_validitydate_for_issuer($issuer)->{$notbefore}}) {
						$ret .= "\t\t\tissuer_owner $issuer_owner_cnt (" . $notbefore . "): ";
						$ret .= join " -> ", @$owner_chain;
						$ret .= "\n";
						$issuer_owner_cnt += 1;
					}
				}
				$ret .= "\t\t---\n";
				my $cert_cnt = 1;
				my $bash_color_bold_str = "\e[1m";
				my $bash_color_dim_str = "\e[2m";
				my $bash_color_reset_str =  "\e[0m";
				for my $cert (sort { $a->{id} <=> $b->{id} } @{$self->certs->{$issuer}}) {
					my $cert_valid = $cert->is_valid($self->tablepostfix);
					$ret .= $bash_color_dim_str if !$cert_valid;
					# my $certid_formatted = sprintf('%-10d', $cert->{id});
					my $crt_sh_id = $cert->get_crtsh_id;
					my $crt_sh_id_formatted = defined $crt_sh_id? $crt_sh_id : "n/a";
					my $crt_id_info_len_max = 30;
					my $certid_info_str = "$cert->{id} (crt.sh: $crt_sh_id_formatted)";
					$certid_info_str .= " " x (max(0, $crt_id_info_len_max - length($certid_info_str)));
					my $cert_not_before = $cert->not_before;
					my $cert_not_after = $cert->not_after;
					my $cert_sig_algo = $cert->sig_algo;
					my $cert_key_algo = $cert->key_algo;
					my $cert_is_rootcert = $cert->is_root_cert;
					my $cert_ca = defined $cert->ca ? $cert->ca : "N";
					my $cert_selfsigned = defined $cert->selfsigned ? $cert->selfsigned : "N";
					my $flag_san = "";
					$flag_san = "subject_in_san" if !($cert->subject eq $self->subject());
					$ret .= "\t\tCertificate $cert_cnt: $certid_info_str  \t $cert_not_before - $cert_not_after  \t(valid: $cert_valid, is_rootcert: $cert_is_rootcert, ca: $cert_ca, selfsigned: $cert_selfsigned, flags: $flag_san, sig_algo: $cert_sig_algo, key_algo: $cert_key_algo)\n";
					if ($cert->is_revoked_cert) {
						$ret .= "  \t\t\t\t\t\t\troot_removals: ";
						foreach ($cert->get_revoked_cert()->flags) {
							$ret .= "$_,";
						}
						$ret .= "\n";
					}
					if ($cert->is_valid($self->tablepostfix)) {
						$ret .= 	"  \t\t\t\t\t\t\tcert_owners: ";
						my $owner_chains_as_strings = [];
						for my $owner_chain (@{$cert->get_owner_chains($self->tablepostfix)}) {
							push @$owner_chains_as_strings, (join " -> ", @$owner_chain);
						}
						$ret .= join " ;; ", @$owner_chains_as_strings;
						$ret .= " (natural owner: " . $cert->is_issued_by_owner($self->tablepostfix) . ")";
						$ret .= "\n";
						$ret .= "  \t\t\t\t\t\t\tstores: ";
						# my $last_storename_leading_chars = "  ";
						# my $bold_switch_on = 1;
						# foreach (@{$cert->get_storenames($self->tablepostfix)}) {
						# 	if (! ((substr $_, 0, 2) eq (substr $last_storename_leading_chars, 0, 2))) {
						# 		# $ret .= "\n\t\t\t\t\t\t\t\t";
						# 		$last_storename_leading_chars = substr $_, 0, 2;
						# 		$ret .= $bash_color_reset_str if $bold_switch_on;
						# 		$ret .= $bash_color_dim_str if ! $bold_switch_on;
						# 		$bold_switch_on = ! $bold_switch_on;
						# 	}
						# 	$ret .= "$_,";
						# }
						# $ret .= $bash_color_reset_str if $bold_switch_on;
						# $ret .= "\n";
						$ret .= "\n";
						my $cert_info_by_rootstore = $cert->get_info_by_rootstore($self->tablepostfix, $self->rootstore_cache);
						for my $rootstore_name (sort keys %$cert_info_by_rootstore) {
							my $valid = $cert_info_by_rootstore->{$rootstore_name}->{'valid'};
							$ret .= "\t\t\t\t\t\t\t\t$rootstore_name : $valid (";
							$ret .= $cert_info_by_rootstore->{$rootstore_name}->{'validity_periods'}->to_string;
							$ret .= ")\n";
						}
						$ret .= "  \t\t\t\t\t\t\tstoreids: ";
						foreach (sort {$a <=> $b} @{$cert->get_storeids($self->tablepostfix, $self->rootstore_cache)}) {
							$ret .= "$_,";
						}
						$ret .= "\n";

						my $revocationinfo_onecrl = $cert->get_onecrl_revocation_info;
						my $revocationinfo_google = $cert->get_google_revocation_info;
						my $revocationinfo_microsoft = $cert->is_microsoft_revoked;
						my $revocationinfo_crl = $cert->get_crl_revocation_dates;
						$revocationinfo_onecrl = defined $revocationinfo_onecrl ? ($revocationinfo_onecrl ? "1 (" . join(',', @$revocationinfo_onecrl) . ")" : "0") : "n/a";
						$revocationinfo_google = defined $revocationinfo_google ? ($revocationinfo_google ? "1 (" . join(',', @$revocationinfo_google) . ")" : "0") : "n/a";
						$revocationinfo_microsoft = defined $revocationinfo_microsoft ? $revocationinfo_microsoft : "n/a";
						$revocationinfo_crl = defined $revocationinfo_crl ? ($revocationinfo_crl ? "1 (" . join(',', @$revocationinfo_crl) . ")" : "0") : "n/a";
						$ret .= "\t\t\t\tRevocation state:\n";
						$ret .= "\t\t\t\t\tOneCRL: $revocationinfo_onecrl\n";
						$ret .= "\t\t\t\t\tGoogle: $revocationinfo_google\n";
						$ret .= "\t\t\t\t\tMicrosoft: $revocationinfo_microsoft\n";
						$ret .= "\t\t\t\t\tCRL: $revocationinfo_crl\n";
					}
					$ret .= $bash_color_reset_str if !$cert_valid;
					$cert_cnt += 1;
				}
				$issuer_cnt += 1;
			}

			# debugging information
			$ret .= "\t Debugging information:\n";
			$ret .= "\t\t debug one_issuer_provides_full_validity: " . (defined $self->{'debug_one_issuer_provides_full_validity'} ? $self->{'debug_one_issuer_provides_full_validity'} : "undef") . "\n";
			$ret .= "\t\t debug valid_natural_owner_cert_exists: " . (defined $self->{'debug_valid_natural_owner_cert_exists'} ? $self->{'debug_valid_natural_owner_cert_exists'} : "undef") . "\n";
			$ret .= "\t\t debug full_validity_by_natural_owner: " . (defined $self->{'debug_full_validity_by_natural_owner'} ? $self->{'debug_full_validity_by_natural_owner'} : "undef") . "\n";
			$ret .= "\t\t debug valid_natural_owner_rootcert_exists: " . (defined $self->{'debug_valid_natural_owner_rootcert_exists'} ? $self->{'debug_valid_natural_owner_rootcert_exists'} : "undef") . "\n";
			$ret .= "\t\t debug natural_owner_cert_trusted_first: " . (defined $self->{'debug_natural_owner_cert_trusted_first'} ? $self->{'debug_natural_owner_cert_trusted_first'} : "undef") . "\n";
			$ret .= "\t\t debug natural_owner_rootcert_trusted_first: " . (defined $self->{'debug_natural_owner_rootcert_trusted_first'} ? $self->{'debug_natural_owner_rootcert_trusted_first'} : "undef") . "\n";
			$ret .= "\t\t debug full_validity_by_natural_owner_rootcert: " . (defined $self->{'debug_full_validity_by_natural_owner_rootcert'} ? $self->{'debug_full_validity_by_natural_owner_rootcert'} : "undef") . "\n";
			$ret .= "\t\t debug natural_owner_certs_combined_provide_full_validity: " . (defined $self->{'debug_natural_owner_certs_combined_provide_full_validity'} ? $self->{'debug_natural_owner_certs_combined_provide_full_validity'} : "undef") . "\n";
			$ret .= "\n";
			$ret .= "\t\t debug earliest_validitydate_ts_overall: " . $self->{'debug_earliest_validitydate_ts_overall'} . "\n";  # already a string
			$ret .= "\t\t debug earliest_validitydate_ts_natural_owner_cert: " . $self->{'debug_earliest_validitydate_ts_natural_owner_cert'} . "\n";  # already a string
			$ret .= "\t\t debug earliest_validitydate_ts_natural_owner_rootcert: " . $self->{'debug_earliest_validitydate_ts_natural_owner_rootcert'} . "\n";  # already a string
			$ret .= "\n";
			$ret .= $self->{'debug_validity'};

			$ret .= ")\n";

			if ($write_to_db) {
				$csc_metadata->save if defined($csc_metadata);
			}
			return $ret;
}

sub readable_id {
	my $self = shift;
	return "CrossSignCert(" . $self->subject . ", " . $self->spki_sha1 .")"
}

sub add_cert {
	my ($self, $cert, $subject) = @_; # $subject must be $cert->subject or any subject in the SAN extension
	my $issuer = $cert->issuer;

	croak("Trying to add cert with subject or SAN entry $subject to cs_cert for $self->{subject}") if !($self->subject eq $subject);

	if (defined($self->certs->{$issuer})) {
		# check if cert already part of this crosssigncert (may happen due to SAN lists)
		for my $known_cert (@{$self->certs->{$issuer}}) {
			if ($known_cert == $cert) {
				return;
			}
		}
	} else {
		$self->certs->{$issuer} //= [];
	}

	push(@{$self->certs->{$issuer}}, $cert);
}

sub is_cs {
	my $self = shift;

	if (scalar keys %{$self->certs} < 2) {
		# only a single issuer certificate
		return 0;
	}

	return 1;
}

sub is_any_cert_valid {
	my $self = shift;

	my $valid_cnt = 0;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			return 1 if ($cert->is_valid($self->tablepostfix) > 0);
		}
	}
	return 0;
}

sub has_validity_gap {
	my $self = shift;

	my @certs;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			push @certs, $cert;
		}
	}

	my @certs_copy = @certs;
	for my $cert (@certs_copy) {
		for my $cert_cur (@certs) {
			if ($cert->not_after lt $cert_cur->not_before or $cert_cur->not_after lt $cert->not_before) {
				return 1;
			}
		}
		# We checked $cert against all others, so remove it from further loops
		my $removed = shift @certs;
		if ($cert != $removed) {
			croak("Unexpected error");
		}
	}

	return 0;
}

sub adds_validity_gap {
	my $self = shift;
	my $cert_candidate = shift;

	my @certs;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			push @certs, $cert;
		}
	}

	for my $cert (@certs) {
		if (_certs_belong_to_same_validity_group($cert_candidate, $cert) == 0) {
			return 1;
		}
	}

	return 0;
}

sub _sort_certs_by_not_before_and_not_after {
	my ($a, $b) = @_;

	my $res_cmp = $a->not_before cmp $b->not_before;
	if ($res_cmp != 0) {
		return $res_cmp;
	}

	$res_cmp = $a->not_after cmp $b->not_after;
	if ($res_cmp != 0) {
		return $res_cmp;
	}

	return $a->id <=> $b->id;
}

sub _certs_belong_to_same_validity_group {
	my ($self, $a, $b) = @_;

	if ($a->not_after lt $b->not_before or $b->not_after lt $a->not_before) {
		# no overlap at all
		return 0;
	} else {
		if (($a->not_before lt $b->not_before and $b->not_after lt $a->not_after)
			or ($b->not_before lt $a->not_before and $a->not_after lt $b->not_after)
		) {
			# full overlap
			return 1;
		} else {
			my $t_not_before;
			my $t_not_after;
			if ($b->not_before lt $a->not_after) {
				$t_not_before = Time::Piece->strptime($b->not_before, "%F %T");
				$t_not_after = Time::Piece->strptime($a->not_after, "%F %T");
			} elsif ($a->not_before lt $b->not_after) {
				$t_not_before = Time::Piece->strptime($a->not_before, "%F %T");
				$t_not_after = Time::Piece->strptime($b->not_after, "%F %T");
			} else {
				croak("Unexpected case");
			}

			my $t_diff_seconds = $t_not_after - $t_not_before;
			my $t_crosssign_minimun_overlap_seconds = $self->_crosssign_minimum_overlap_days * 24*60*60;
			if ($t_diff_seconds < $t_crosssign_minimun_overlap_seconds) {
				# overlap is too small
				return 0;
			} else {
				return 1;
			}
		}
	}
	croak("Should not reach here!");
}

sub get_certs_by_validity_subgroups {
	# returns all certs that belong to a CS-subgroup, i.e., that have sufficiently
	# overlapping validity periods
	my $self = shift;

	croak('Already a filtered cscert') if $self->is_subgroup_cscert;

	return $self->{'certs_by_validity_subgroups'} if defined($self->{'certs_by_validity_subgroups'});

	my @certs_by_validity_subgroups;
	my $certs = $self->get_certs;

	my $current_group = [];
	for my $cert (sort { _sort_certs_by_not_before_and_not_after($a, $b) } @$certs) {

		my $needs_new_group = 0;
		for my $groupcert (@$current_group) {
			if ($self->_certs_belong_to_same_validity_group($groupcert, $cert) != 1) {
				$needs_new_group = 1;
				last;
			}
		}

		if ($needs_new_group) {
			# We are done with the current group, so store it away
			push(@certs_by_validity_subgroups, $current_group);

			my @new_group;
			# Add certificates that are part of both, the old and the new group
			for my $groupcert (@$current_group) {
				if ($self->_certs_belong_to_same_validity_group($groupcert, $cert) == 1) {
					push(@new_group, $groupcert);
				}
			}
			push(@new_group, $cert);
			$current_group = \@new_group;
		} else {
			push(@$current_group, $cert);
		}
	}
	# We are done with all certs, store away the last group
	push(@certs_by_validity_subgroups, $current_group);
	$self->{'certs_by_validity_subgroups'} = \@certs_by_validity_subgroups;

	return $self->{'certs_by_validity_subgroups'};
}

sub get_subgroups_as_cscerts {
	my $self = shift;

	croak('Already a filtered cscert') if $self->is_subgroup_cscert;

	return $self->{'subgroup_cscerts'} if defined($self->{'subgroup_cscerts'});

	my @subgroup_cscerts;
	my $subgroups = $self->get_certs_by_validity_subgroups;
	for my $subgroup (@$subgroups) {
		my $csc_obj = CertReader::App::EvalCrosssign::CrosssignCert->new(
			db => $self->db,
			tablepostfix => $self->tablepostfix,
			subject => $self->subject,
			csc_id => $self->csc_id,
			rootstore_cache => $self->{'rootstore_cache'},
			is_subgroup_cscert => 1,
			worker_prefix => $self->worker_prefix,
		);

		for my $cert (@$subgroup) {
			$csc_obj->add_cert($cert, $cert->subject);
		}

		if ($csc_obj->is_cs) {
			push(@subgroup_cscerts, $csc_obj);
			if ($csc_obj->has_validity_gap) {
				say ("ERROR: Subgroup has validity gap");
				say $csc_obj;
				croak("Logic error in subgroup creation")
			}
		}
	}

	$self->{'subgroup_cscerts'} = \@subgroup_cscerts;

	return $self->{'subgroup_cscerts'};
}

sub is_cs_valid {
	# Tests if this is a cross-sign certificate under validity aspects, i.e., at
	# least two certificates of different issuers must be valid.
	my $self = shift;

	my $valid_cnt = 0;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			my $cert_valid = $cert->is_valid($self->tablepostfix);
			if ($cert_valid > 0) {
				$valid_cnt += 1;
				last;
			}
		}
		return 1 if $valid_cnt > 1;
	}
	return 0;
}

sub _classify {
	my $self = shift;

	return if defined($self->{'_classified'});

	$self->{'_cs_rootcert'} = 0;
	$self->{'_cs_intermediate'} = 0;
	$self->{'_cs_leaf'} = 0;
	$self->{'_cs_leafmix'} = 0;

	$self->{'_cs_multiSignAlgs'} = 0;

	$self->{'_cs_expandingStores'} = 0;
	$self->{'_cs_expandingTime'} = 0;
	$self->{'_cs_alternPaths'} = 0;
	$self->{'_cs_bootstrapping'} = 0;

	my $rootcert_issuers = {};
	my $intermediate_issuers = {};
	my $leaf_issuers = {};

	my $issuers_by_signature_algorithms = {};

	my $rootstore_info_by_issuer = {};
	my $rootstore_info_full = {};
	my $rootstore_info_natural_owner_certs_combined = {};
	my $rootstore_info_natural_owner_rootcerts_combined = {};

	my $valid_natural_owner_certs = [];
	my $natural_owner_issuers = {};
	my $natural_owner_root_issuers = {};

	# TODO does not consider that certs can be from the same issuer
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			my $is_valid = $cert->is_valid($self->tablepostfix);
			if($is_valid == 0) {
				# we ignore invalid certs
			} else {
				if ($cert->ca) {
					if ($is_valid == 2 or $is_valid == 3 or $is_valid == -1) {
						$rootcert_issuers->{$issuer} = 1;
					} elsif ($is_valid == 1) {
						$intermediate_issuers->{$issuer} = 1;
					}
				} else {
					if ($is_valid != 0) { # There are leaf certificates in root stores
						$leaf_issuers->{$issuer} = 1;
					}
				}

				my $is_natural_owner_cert = 0;
				my $is_natural_owner_rootcert = 0;
				if ($cert->is_issued_by_owner($self->tablepostfix)) {
					$is_natural_owner_cert = 1;
					push(@$valid_natural_owner_certs, $cert);
					$natural_owner_issuers->{$issuer} = 1;
					if ($cert->is_root_cert and (defined $cert->selfsigned and $cert->selfsigned)) {
						$is_natural_owner_rootcert = 1;
						$natural_owner_root_issuers->{$issuer} = 1;
					}
				}

				if ($cert->selfsigned) {
					;  # can only serve as trust anchor whose signature is usually not checked
				} else {
					$issuers_by_signature_algorithms->{$cert->sig_algo} //= {};
					$issuers_by_signature_algorithms->{$cert->sig_algo}->{$issuer} = 1;
				}

				my $cert_info_by_rootstore = $cert->get_info_by_rootstore($self->tablepostfix, $self->rootstore_cache, $self->worker_prefix);
				for my $rootstore_name (keys %$cert_info_by_rootstore) {
					$rootstore_info_by_issuer->{$issuer} //= {};
					$rootstore_info_by_issuer->{$issuer}->{$rootstore_name} //= {};
					$rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'valid'} //= 0;
					$rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();

					$rootstore_info_full->{$rootstore_name} //= {};
					$rootstore_info_full->{$rootstore_name}->{'valid'} //= 0;
					$rootstore_info_full->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();

					if ($is_natural_owner_cert) {
						$rootstore_info_natural_owner_certs_combined->{$rootstore_name} //= {};
						$rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'valid'} //= 0;
						$rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();
					}
					if ($is_natural_owner_rootcert) {
						$rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name} //= {};
						$rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'valid'} //= 0;
						$rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'validity_periods'} //= CertReader::CA::ValidityPeriods->new();
					}

					if ($cert_info_by_rootstore->{$rootstore_name}->{'valid'}) {
						$rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'valid'} = $cert_info_by_rootstore->{$rootstore_name}->{'valid'};
						$rootstore_info_full->{$rootstore_name}->{'valid'} = $cert_info_by_rootstore->{$rootstore_name}->{'valid'};
						$rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'valid'} = $cert_info_by_rootstore->{$rootstore_name}->{'valid'} if $is_natural_owner_cert;
						$rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'valid'} = $cert_info_by_rootstore->{$rootstore_name}->{'valid'} if $is_natural_owner_rootcert;
					}
					for my $period (@{$cert_info_by_rootstore->{$rootstore_name}->{'validity_periods'}->get_periods}) {
						$rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'validity_periods'}->add_period($period->get_notbefore, $period->get_notafter);
						$rootstore_info_full->{$rootstore_name}->{'validity_periods'}->add_period($period->get_notbefore, $period->get_notafter);
						$rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'validity_periods'}->add_period($period->get_notbefore, $period->get_notafter) if $is_natural_owner_cert;
						$rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'validity_periods'}->add_period($period->get_notbefore, $period->get_notafter) if $is_natural_owner_rootcert;
					}
				}
			}
		}
	}

	my $cnt_rootcert_issuers = scalar keys %$rootcert_issuers;
	my $cnt_intermediate_issuers = scalar keys %$intermediate_issuers;
	my $cnt_leaf_issuers = scalar keys %$leaf_issuers;

	if ($cnt_rootcert_issuers > 0 and $cnt_intermediate_issuers > 0) {
		if ($cnt_rootcert_issuers == 1 and $cnt_intermediate_issuers == 1) {
			# must not be the same issuer
			if (! ((keys %$rootcert_issuers)[0] eq (keys %$intermediate_issuers)[0]) ) {
				$self->{'_cs_rootcert'} = 1;
			}
		} else {
			$self->{'_cs_rootcert'} = 1;
		}
	}
	if ($cnt_rootcert_issuers == 0 and $cnt_intermediate_issuers > 1) {
		$self->{'_cs_intermediate'} = 1;
	}
	if ($cnt_rootcert_issuers == 0 and $cnt_intermediate_issuers == 0 and $cnt_leaf_issuers > 1) {
		$self->{'_cs_leaf'} = 1;
	}

	if ($cnt_leaf_issuers > 0 and ($cnt_rootcert_issuers > 0 or $cnt_intermediate_issuers > 0)) {
		# We do not check for distinct issuers here; These cases are interesting in general. Just filter out manually.
		$self->{'_cs_leafmix'} = 1;
	}

	my $all_sign_algos_covered_by_one_issuer = 0;
	ISSUERS: for my $issuer (keys %{$self->certs}) {
		for my $sign_algo (keys %$issuers_by_signature_algorithms) {
			if (defined $issuers_by_signature_algorithms->{$sign_algo}->{$issuer}) {
				next ISSUERS if (not $issuers_by_signature_algorithms->{$sign_algo}->{$issuer});
			} else {
				next ISSUERS;
			}
		}
		$all_sign_algos_covered_by_one_issuer = 1;
		last ISSUERS;
	}
	if (not $all_sign_algos_covered_by_one_issuer) {
		$self->{'_cs_multiSignAlgs'} = 1;
	}

	my $grace_period_seconds = 2592000;  # 60 sec/min * 60 min/h * 24 h/d * 30 d/month = 2592000 sec/month
	my $one_issuer_provides_full_validity = 0;
	my $one_issuer_provides_full_validity_ignoring_periods = 0;
	my $one_issuer_provides_full_validity_ignoring_periods_and_was_first = 0;
	my $natural_issuer_covers_all_stores_ignoring_periods = 0;
	my $natural_issuer_covers_all_stores_ignoring_periods_and_was_first = 0;
	my $natural_owner_certs_combined_provide_full_validity;
	my $valid_natural_owner_cert_exists = 0;
	my $natural_owner_cert_trusted_first = 0;
	my $natural_owner_cert_trusted_first_for_all_rootstores = 0;
	my $valid_natural_owner_rootcert_exists = 0;
	my $natural_owner_rootcert_trusted_first = 0;
	my $natural_owner_rootcert_trusted_first_for_all_rootstores = 0;
	my $natural_owner_rootcert_covers_all_stores_ignoring_periods = 0;
	my $natural_owner_rootcert_covers_all_stores_ignoring_periods_trusted_first = 0;
	my $full_validity_by_natural_owner = 0;
	my $full_validity_by_natural_owner_rootcert = 0;

	# derive $one_issuer_provides_full_validity
	ISSUER: for my $issuer (keys %$rootstore_info_by_issuer) {
		my $issuer_covers_all_stores_with_all_periods = 1;
		my $issuer_covers_all_stores_ignoring_periods = 1;
		my $issuer_is_first = 1;

		for my $rootstore_name (keys %{$rootstore_info_full}) {
			unless (defined $rootstore_info_by_issuer->{$issuer}->{$rootstore_name}) {
				$issuer_covers_all_stores_ignoring_periods = 0;
				$issuer_covers_all_stores_with_all_periods = 0;
				next ISSUER;  # nothing "good" can happen anymore; speed up
			}
			if ($rootstore_info_full->{$rootstore_name}->{'valid'}) {
				if (! $rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'valid'}) {
					$issuer_covers_all_stores_ignoring_periods = 0;
					$issuer_covers_all_stores_with_all_periods = 0;
					next ISSUER;  # nothing "good" can happen anymore; speed up
				}

				unless ($rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'validity_periods'}->starts_earlier_than($rootstore_info_full->{$rootstore_name}->{'validity_periods'}, $grace_period_seconds)) {
					$issuer_is_first = 0;
				}

				for my $period (@{$rootstore_info_full->{$rootstore_name}->{'validity_periods'}->get_periods}) {
					if (! $rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'validity_periods'}->covers_period($period, $grace_period_seconds)) {
						$issuer_covers_all_stores_with_all_periods = 0;
						# continue as $issuer_covers_all_stores_ignoring_periods can still be true
					}
				}
			}
		}

		if ($issuer_covers_all_stores_ignoring_periods) {
			$one_issuer_provides_full_validity_ignoring_periods = 1;
			if ($issuer_is_first) {
				$one_issuer_provides_full_validity_ignoring_periods_and_was_first = 1;
			}
			if (defined $natural_owner_issuers->{$issuer} and $natural_owner_issuers->{$issuer}) {
				$natural_issuer_covers_all_stores_ignoring_periods = 1;
				if ($issuer_is_first) {
					$natural_issuer_covers_all_stores_ignoring_periods_and_was_first = 1;
				}
				if (defined $natural_owner_root_issuers->{$issuer} and $natural_owner_root_issuers->{$issuer}) {
					$natural_owner_rootcert_covers_all_stores_ignoring_periods = 1;
					if ($issuer_is_first) {
						$natural_owner_rootcert_covers_all_stores_ignoring_periods_trusted_first = 1;
					}
				}
			}
		}
		if ($issuer_covers_all_stores_with_all_periods) {
			$one_issuer_provides_full_validity = 1;
			if (defined $natural_owner_issuers->{$issuer}) {
				if ($natural_owner_issuers->{$issuer}) {
					$full_validity_by_natural_owner = 1;
				}
			}
		}
	}

	# derive $natural_owner_certs_combined_provide_full_validity
	$natural_owner_certs_combined_provide_full_validity = 1;
	for my $rootstore_name (keys %{$rootstore_info_full}) {
		if (defined $rootstore_info_natural_owner_certs_combined->{$rootstore_name}) {
			if ($rootstore_info_full->{$rootstore_name}->{'valid'}) {
				if (! $rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'valid'}) {
					$natural_owner_certs_combined_provide_full_validity = 0;
				}
				for my $period (@{$rootstore_info_full->{$rootstore_name}->{'validity_periods'}->get_periods}) {
					if (! $rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'validity_periods'}->covers_period($period, $grace_period_seconds)) {
						$natural_owner_certs_combined_provide_full_validity = 0;
					}
				}
			}
		} else {
			$natural_owner_certs_combined_provide_full_validity = 0;
		}
	}

	# derive $full_validity_by_natural_owner_rootcert
	$full_validity_by_natural_owner_rootcert = 1;
	for my $rootstore_name (keys %{$rootstore_info_full}) {
		if (defined $rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}) {
			if ($rootstore_info_full->{$rootstore_name}->{'valid'}) {
				if (! $rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'valid'}) {
					$full_validity_by_natural_owner_rootcert = 0;
				}
				for my $period (@{$rootstore_info_full->{$rootstore_name}->{'validity_periods'}->get_periods}) {
					if (! $rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'validity_periods'}->covers_period($period, $grace_period_seconds)) {
						$full_validity_by_natural_owner_rootcert = 0;
					}
				}
			}
		} else {
			$full_validity_by_natural_owner_rootcert = 0;
		}
	}

	my $earliest_validitydate_ts_natural_owner_cert;
	my $earliest_validitydate_ts_natural_owner_rootcert;
	my $earliest_validitydate_ts_overall;
	NATURAL_OWNER_CERT: for my $natural_owner_cert (@$valid_natural_owner_certs) {
		my $cur_natural_owner_cert_is_first_for_all_stores = 1;

		$valid_natural_owner_cert_exists = 1;
		$valid_natural_owner_rootcert_exists = 1 if $natural_owner_cert->is_root_cert and (defined $natural_owner_cert->selfsigned and $natural_owner_cert->selfsigned);

		my $cert_rootstore_info = $natural_owner_cert->get_info_by_rootstore($self->tablepostfix, $self->rootstore_cache, $self->worker_prefix);
		for my $rootstore_name (keys %$rootstore_info_full) {
			if ($rootstore_info_full->{$rootstore_name}->{'valid'}) {

				if (defined $rootstore_info_full->{$rootstore_name}->{'validity_periods'}->get_earliest_period) {
					$earliest_validitydate_ts_overall //= $rootstore_info_full->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts;
					$earliest_validitydate_ts_overall = min($earliest_validitydate_ts_overall, $rootstore_info_full->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts);
				}

				if (defined $cert_rootstore_info->{$rootstore_name} and $cert_rootstore_info->{$rootstore_name}->{'valid'}) {
					if (defined $rootstore_info_full->{$rootstore_name}->{'validity_periods'}) {
						if (defined $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}) {

							if (defined $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->get_earliest_period) {
								if (defined $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts) {
									$earliest_validitydate_ts_natural_owner_cert //= $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts;
									$earliest_validitydate_ts_natural_owner_cert = min($earliest_validitydate_ts_natural_owner_cert, $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts);
									if ($natural_owner_cert->is_root_cert and (defined $natural_owner_cert->selfsigned and $natural_owner_cert->selfsigned)) {
										$earliest_validitydate_ts_natural_owner_rootcert //= $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts;
										$earliest_validitydate_ts_natural_owner_rootcert = min($earliest_validitydate_ts_natural_owner_rootcert, $cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->get_earliest_period->get_notbefore_ts);
									}
								}
							}

							if ($cert_rootstore_info->{$rootstore_name}->{'validity_periods'}->starts_earlier_than($rootstore_info_full->{$rootstore_name}->{'validity_periods'}, $grace_period_seconds)) {
								;
							} else {
								$cur_natural_owner_cert_is_first_for_all_stores = 0;
							}
						} else {
							$cur_natural_owner_cert_is_first_for_all_stores = 0;
						}
					} else {
						;
					}
				} else {
					$cur_natural_owner_cert_is_first_for_all_stores = 0;
				}
			}
		}
		if ($cur_natural_owner_cert_is_first_for_all_stores) {
			$natural_owner_cert_trusted_first_for_all_rootstores = 1;
			$natural_owner_rootcert_trusted_first_for_all_rootstores = 1 if $natural_owner_cert->is_root_cert and (defined $natural_owner_cert->selfsigned and $natural_owner_cert->selfsigned);
		}
	}
	if (defined $earliest_validitydate_ts_overall) {
		if (defined $earliest_validitydate_ts_natural_owner_cert and ($earliest_validitydate_ts_natural_owner_cert <= ($earliest_validitydate_ts_overall + $grace_period_seconds))) {
			$natural_owner_cert_trusted_first = 1;
		} else {
			$natural_owner_cert_trusted_first = 0;
		}
		if (defined $earliest_validitydate_ts_natural_owner_rootcert and ($earliest_validitydate_ts_natural_owner_rootcert <= ($earliest_validitydate_ts_overall + $grace_period_seconds))) {
			$natural_owner_rootcert_trusted_first = 1;
		} else {
			$natural_owner_rootcert_trusted_first = 0;
		}
	} else {
		$natural_owner_cert_trusted_first = 1;
		$natural_owner_rootcert_trusted_first = 1;
	}

	$self->{'debug_one_issuer_provides_full_validity'} = $one_issuer_provides_full_validity;
	$self->{'debug_valid_natural_owner_cert_exists'} = $valid_natural_owner_cert_exists;
	$self->{'debug_full_validity_by_natural_owner'} = $full_validity_by_natural_owner;
	$self->{'debug_valid_natural_owner_rootcert_exists'} = $valid_natural_owner_rootcert_exists;
	$self->{'debug_natural_owner_cert_trusted_first'} = $natural_owner_cert_trusted_first;
	$self->{'debug_natural_owner_rootcert_trusted_first'} = $natural_owner_rootcert_trusted_first;
	$self->{'debug_full_validity_by_natural_owner_rootcert'} = $full_validity_by_natural_owner_rootcert;
	$self->{'debug_natural_owner_certs_combined_provide_full_validity'} = $natural_owner_certs_combined_provide_full_validity;
	$self->{'debug_earliest_validitydate_ts_overall'} = defined $earliest_validitydate_ts_overall ? time2str("%Y-%m-%d %H:%M:%S", $earliest_validitydate_ts_overall, "UTC") . " ($earliest_validitydate_ts_overall)" : "undef";
	$self->{'debug_earliest_validitydate_ts_natural_owner_cert'} = defined $earliest_validitydate_ts_natural_owner_cert ? time2str("%Y-%m-%d %H:%M:%S", $earliest_validitydate_ts_natural_owner_cert, "UTC") . " ($earliest_validitydate_ts_natural_owner_cert)" : "undef";
	$self->{'debug_earliest_validitydate_ts_natural_owner_rootcert'} = defined $earliest_validitydate_ts_natural_owner_rootcert ? time2str("%Y-%m-%d %H:%M:%S", $earliest_validitydate_ts_natural_owner_rootcert, "UTC") . " ($earliest_validitydate_ts_natural_owner_rootcert)" : "undef";
	my $debug_validity_str = "";
	$debug_validity_str .= "\t\trootstore_info_full\n";
	for my $rootstore_name (sort keys %$rootstore_info_full) {
		my $debug_out_valid = $rootstore_info_full->{$rootstore_name}->{'valid'};
		$debug_validity_str .= "\t\t\t$rootstore_name : $debug_out_valid (";
		$debug_validity_str .= $rootstore_info_full->{$rootstore_name}->{'validity_periods'}->to_string;
		$debug_validity_str .= ")\n";
	}
	#
	$debug_validity_str .= "\t\trootstore_info_natural_owner_certs_combined\n";
	for my $rootstore_name (sort keys %$rootstore_info_natural_owner_certs_combined) {
		my $debug_out_valid = $rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'valid'};
		$debug_validity_str .= "\t\t\t$rootstore_name : $debug_out_valid (";
		$debug_validity_str .= $rootstore_info_natural_owner_certs_combined->{$rootstore_name}->{'validity_periods'}->to_string;
		$debug_validity_str .= ")\n";
	}
	#
	$debug_validity_str .= "\t\trootstore_info_natural_owner_ROOTcerts_combined\n";
	for my $rootstore_name (sort keys %$rootstore_info_natural_owner_rootcerts_combined) {
		my $debug_out_valid = $rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'valid'};
		$debug_validity_str .= "\t\t\t$rootstore_name : $debug_out_valid (";
		$debug_validity_str .= $rootstore_info_natural_owner_rootcerts_combined->{$rootstore_name}->{'validity_periods'}->to_string;
		$debug_validity_str .= ")\n";
	}
	#
	for my $issuer (keys %{$self->certs}) {
		if (defined $rootstore_info_by_issuer->{$issuer}) {
			$debug_validity_str .= "\t\trootstore_info $issuer\n";
			for my $rootstore_name (sort keys %{$rootstore_info_by_issuer->{$issuer}}) {
				my $debug_out_valid = $rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'valid'};
				$debug_validity_str .= "\t\t\t$rootstore_name : $debug_out_valid (";
				$debug_validity_str .= $rootstore_info_by_issuer->{$issuer}->{$rootstore_name}->{'validity_periods'}->to_string;
				$debug_validity_str .= ")\n";
			}
		}
	}
	$self->{'debug_validity'} = $debug_validity_str;

	if ($one_issuer_provides_full_validity) {
		if ($valid_natural_owner_cert_exists) {  # TODO what about (yet) invalid natural owner cert?
			if ($full_validity_by_natural_owner) {
				if ($valid_natural_owner_rootcert_exists) {
					if ($natural_owner_rootcert_trusted_first) {
						if ($full_validity_by_natural_owner_rootcert) {
							$self->{'_cs_alternPaths'} = 1;
						} else {
							if ($natural_owner_rootcert_covers_all_stores_ignoring_periods_trusted_first) {
								$self->{'_cs_expandingTime'} = 1;
							} else {
								$self->{'_cs_expandingStores'} = 1;
							}
						}
					} else {
						$self->{'_cs_bootstrapping'} = 1;  # internal bootstrapping
					}
				} else {
					$self->{'_cs_alternPaths'} = 1;
				}
			} else {
				if ($natural_owner_certs_combined_provide_full_validity) {
					if ($valid_natural_owner_rootcert_exists) {
						if ($natural_owner_rootcert_trusted_first) {
							if ($natural_owner_rootcert_covers_all_stores_ignoring_periods_trusted_first) {
								$self->{'_cs_expandingTime'} = 1;
							} else {
								$self->{'_cs_expandingStores'} = 1;
							}
						} else {
							$self->{'_cs_bootstrapping'} = 1;  # internal bootstrapping
						}
					} else {
						if ($one_issuer_provides_full_validity_ignoring_periods_and_was_first) {
							$self->{'_cs_expandingTime'} = 1;
						} else {
							$self->{'_cs_expandingStores'} = 1;
						}
					}
				} else {
					$self->{'_cs_bootstrapping'} = 1;  # external bootstrapping
				}
			}
		} else {
			$self->{'_cs_alternPaths'} = 1;
		}
	} else {
		if ($valid_natural_owner_cert_exists) {
			if ($natural_owner_cert_trusted_first) {  # TODO what about (yet) invalid natural owner cert?
				if ($valid_natural_owner_rootcert_exists) {
					if ($natural_owner_rootcert_trusted_first) {
						if ($natural_owner_rootcert_covers_all_stores_ignoring_periods_trusted_first) {
							$self->{'_cs_expandingTime'} = 1;
						} else {
							$self->{'_cs_expandingStores'} = 1;
						}
					} else {
						$self->{'_cs_bootstrapping'} = 1;  # internal bootstrapping
					}
				} else {
					if ($natural_issuer_covers_all_stores_ignoring_periods_and_was_first) {
						$self->{'_cs_expandingTime'} = 1;
					} else {
						$self->{'_cs_expandingStores'} = 1;
					}
				}
			} else {
				if ($natural_owner_certs_combined_provide_full_validity) {
					if ($valid_natural_owner_rootcert_exists) {
						if ($natural_owner_rootcert_trusted_first) {
							if ($natural_owner_rootcert_covers_all_stores_ignoring_periods_trusted_first) {
								$self->{'_cs_expandingTime'} = 1;
							} else {
								$self->{'_cs_expandingStores'} = 1;
							}
						} else {
							$self->{'_cs_bootstrapping'} = 1;  # internal bootstrapping
						}
					} else {
						if ($one_issuer_provides_full_validity_ignoring_periods_and_was_first) {
							$self->{'_cs_expandingTime'} = 1;
						} else {
							$self->{'_cs_expandingStores'} = 1;
						}
					}
				} else {
					$self->{'_cs_bootstrapping'} = 1;  # external bootstrapping
				}
			}
		} else {
			if ($one_issuer_provides_full_validity_ignoring_periods_and_was_first) {
				$self->{'_cs_expandingTime'} = 1;
			} else {
				$self->{'_cs_expandingStores'} = 1;
			}
		}
	}

	$self->{'_classified'} = 1;
}

sub is_cs_rootcert {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_rootcert'} == 1);
	return 0;
}

sub is_cs_intermediate {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_intermediate'} == 1);
	return 0;
}

sub is_cs_leaf {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_leaf'} == 1);
	return 0;
}

sub is_cs_leafmix {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_leafmix'} == 1);
	return 0;
}

sub is_cs_multiSignAlgs {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_multiSignAlgs'} == 1);
	return 0;
}

sub is_cs_expandingStores {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_expandingStores'} == 1);
	return 0;
}

sub is_cs_expandingTime {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_expandingTime'} == 1);
	return 0;
}

sub is_cs_alternPaths {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_alternPaths'} == 1);
	return 0;
}

sub is_cs_bootstrapping {
	my $self = shift;
	$self->_classify;
	return 1 if ($self->{'_cs_bootstrapping'} == 1);
	return 0;
}

sub _classify_ownerbased {
	my $self = shift;

	return if defined($self->{'_classified_ownerbased'});

	$self->{'_cs_ca_intern_singlecert'} = 0;
	$self->{'_cs_ca_intern_multicert'} = 0;
	$self->{'_cs_ca_intern_multicert_oneCA'} = 0;
	$self->{'_cs_ca_intern_multiCAs'} = 0;
	$self->{'_cs_ca_extern_singlecert'} = 0;
	$self->{'_cs_ca_extern_multicert'} = 0;
	$self->{'_cs_ca_extern_multicert_oneCA'} = 0;
	$self->{'_cs_ca_extern_multiCAs'} = 0;
	$self->{'_cs_leaf_singleCA'} = 0;
	$self->{'_cs_leaf_multiCAs'} = 0;
	$self->{'_cs_leaf_singlecert_oneCA'} = 0;
	$self->{'_cs_leaf_multicert_oneCA'} = 0;

	if ($self->is_cs_valid($self->tablepostfix) != 0) {

		my $issuer_certs_intern_cnt = 0;
		my $issuer_certs_extern_cnt = 0;
		my $issuers_intern_owners = {};
		my $issuers_extern_owners = {};

		my $owners_certs = $self->get_owners_all_certs;

		for my $issuer (keys %{$self->certs}) {
			my $owners_issuer = $self->get_owners_for_issuer($issuer);
			for my $owner_issuer (@$owners_issuer) {

				next if $owner_issuer eq "Warning_invalid_cacert";

				if (grep {$_ eq $owner_issuer} @$owners_certs) {
					$issuer_certs_intern_cnt += 1;
					$issuers_intern_owners->{$owner_issuer} //= 0;
					$issuers_intern_owners->{$owner_issuer} += 1;
				} else {
					$issuer_certs_extern_cnt += 1;
					$issuers_extern_owners->{$owner_issuer} //= 0;
					$issuers_extern_owners->{$owner_issuer} += 1;
				}

			}
		}

		my $issuers_intern_owners_cnt = scalar (keys %$issuers_intern_owners);
		my $issuers_extern_owners_cnt = scalar (keys %$issuers_extern_owners);

		if ($self->is_cs_rootcert or $self->is_cs_intermediate) {
			$self->{'_cs_ca_intern_singlecert'} = 1 if ($issuer_certs_intern_cnt == 1);
			$self->{'_cs_ca_intern_multicert'} = 1 if ($issuer_certs_intern_cnt >= 2);
			$self->{'_cs_ca_intern_multicert_oneCA'} = 1 if grep {$issuers_intern_owners->{$_} >= 2} (keys %$issuers_intern_owners);
			$self->{'_cs_ca_intern_multiCAs'} = 1 if $issuers_intern_owners_cnt >= 2;

			$self->{'_cs_ca_extern_singlecert'} = 1 if ($issuer_certs_extern_cnt == 1);
			$self->{'_cs_ca_extern_multicert'} = 1 if ($issuer_certs_extern_cnt >= 2);
			$self->{'_cs_ca_extern_multicert_oneCA'} = 1 if grep {$issuers_extern_owners->{$_} >= 2} (keys %$issuers_extern_owners);
			$self->{'_cs_ca_extern_multiCAs'} = 1 if $issuers_extern_owners_cnt >= 2;
		} else {
			# TODO this could also be an "internal" leaf certificate, c.f. csc_id: 3061 (even when its not a leaf cert)
			$self->{'_cs_leaf_singleCA'} = 1 if $issuers_extern_owners_cnt == 1;
			$self->{'_cs_leaf_multiCAs'} = 1 if $issuers_extern_owners_cnt >= 2;
			$self->{'_cs_leaf_singlecert_oneCA'} = 1 if grep {$issuers_extern_owners->{$_} == 1} (keys %$issuers_extern_owners);
			$self->{'_cs_leaf_multicert_oneCA'} = 1 if grep {$issuers_extern_owners->{$_} >= 2} (keys %$issuers_extern_owners);
		}

	}

	$self->{'_classified_ownerbased'} = 1;
}


sub is_cs_ca_intern_singlecert {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_intern_singlecert'};
}
sub is_cs_ca_intern_multicert {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_intern_multicert'};
}
sub is_cs_ca_intern_multicert_oneCA {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_intern_multicert_oneCA'};
}
sub is_cs_ca_intern_multiCAs {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_intern_multiCAs'};
}
sub is_cs_ca_extern_singlecert {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_extern_singlecert'};
}
sub is_cs_ca_extern_multicert {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_extern_multicert'};
}
sub is_cs_ca_extern_multicert_oneCA {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_extern_multicert_oneCA'};
}
sub is_cs_ca_extern_multiCAs {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_ca_extern_multiCAs'};
}
sub is_cs_leaf_singleCA {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_leaf_singleCA'};
}
sub is_cs_leaf_multiCAs {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_leaf_multiCAs'};
}
sub is_cs_leaf_singlecert_oneCA {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_leaf_singlecert_oneCA'};
}
sub is_cs_leaf_multicert_oneCA {
	my $self = shift;
	$self->_classify_ownerbased;
	return $self->{'_cs_leaf_multicert_oneCA'};
}


sub has_rootcert {
	my $self = shift;

	my $valid_cnt = 0;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			my $cert_valid = $cert->is_valid($self->tablepostfix);
			return 1 if ($cert_valid >= 2);
		}
	}
	return 0;
}

sub has_revokedcert {
	my $self = shift;

	my $valid_cnt = 0;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			my $cert_valid = $cert->is_valid($self->tablepostfix);
			return 1 if ($cert_valid eq -1 or $cert_valid eq 3);
		}
	}
	return 0;
}

sub get_issuers_sorted {
	my $self = shift;

	return $self->{'_issuers_sorted'} if defined($self->{'_issuers_sorted'});

	my @issuers;
	for my $issuer (sort keys %{$self->certs}) {
		push(@issuers, $issuer);
	}
	$self->{'_issuers_sorted'} = \@issuers;

	return $self->{'_issuers_sorted'};
}

sub get_issuer_cnt {
	my $self = shift;
	return scalar keys %{$self->certs};
}

sub get_issuer_cnt_valid {
	my $self = shift;
	my $issuer_cnt = 0;

	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			if ($cert->is_valid($self->tablepostfix) > 0) {
				$issuer_cnt += 1;
				last;
			}
		}
	}

	return $issuer_cnt;
}

sub get_cert_cnt {
	my $self = shift;
	my $cnt = 0;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			$cnt += 1;
		}
	}
	return $cnt;
}

sub get_cert_cnt_valid {
	my $self = shift;
	my $cnt = 0;
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			if ($cert->is_valid($self->tablepostfix) > 0) {
				$cnt += 1;
			}
		}
	}
	return $cnt;
}

sub get_certs {
	my $self = shift;
	my $list = [];
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			push(@$list, $cert);
		}
	}
	return $list;
}

sub _get_cert_any {
	my $self = shift;
	my @issuers = keys %{$self->certs};
	my $issuer_any = $issuers[0];
	return @{$self->certs->{$issuer_any}}[0];
}

sub key_mod {
	my $self = shift;
	return $self->_get_cert_any->key_mod;
}

sub spki_sha1 {
	my $self = shift;
	return $self->_get_cert_any->spki_sha1;
}

sub get_storelabels_by_issuer {
	my $self = shift;
	my $fh = shift;
	$fh = \*STDOUT if !defined($fh);
	my $postfix = $self->tablepostfix;

	my $storelabels_by_issuer = {};
	for my $issuer (sort keys %{$self->certs}) {
		my %labels;
		for my $cert (@{$self->certs->{$issuer}}) {
			my $certid = $cert->id;

			# First get all the trees for the certificate(s)
			# TODO: verify_attime
			my $vtiter = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
				db => $self->db,
				inject_results => 1,
				sql => "select * from verify_tree_$postfix where certificate = $certid order by store;",
			);
			my $cert_valid = 0;
			while ( my $vt = $vtiter->next ) {
				$cert_valid = 1;
				my $rootstore = $vt->rootstore;
				for my $storelabel (@{$rootstore->stores}) {
					$labels{$storelabel} = 1;
				}
			}
			croak "ERROR while iterating over paths: " . $vtiter->error if $vtiter->error;

			if (!$vtiter->total) {
				# No paths in db, check if this is a root certificate
				my $rootstore = CertReader::DB::RootCerts->new(certificate => $certid);
				if ( $rootstore->load(use_key => 'certificate', speculative => 1) ) {
					$cert_valid = 1;
					for my $storelabel (@{$rootstore->stores}) {
						$labels{$storelabel} = 1;
					}
				}
			}

			say $fh "WARNING: No trusted path for certificate $certid" if (!$cert_valid);
		my @storelabels = sort keys %labels;
		$storelabels_by_issuer->{$issuer} = \@storelabels;
		# say Dumper($storelabels_by_issuer->{$issuer});
		}
	}
	return $storelabels_by_issuer;
}

sub get_issuerids_for_issuer {
	my ($self, $issuer) = @_;

	$self->{_issuer_ids} //= {};
	return $self->{_issuer_ids}->{$issuer} if defined($self->{_issuer_ids}->{$issuer});

	my $issuer_ids = [];
	for my $cert (@{$self->certs->{$issuer}}) {
		for my $issuer_id (@{$cert->get_issuer_ids($self->tablepostfix)}) {
			if (!(grep {$_ == $issuer_id} @$issuer_ids)) {
				push(@$issuer_ids, $issuer_id);
			}
		}
	}

	$self->{_issuer_ids}->{$issuer} = $issuer_ids;
	return $issuer_ids;
}

sub get_issuercerts_for_issuer {
	my ($self, $issuer) = @_;
	my $postfix = $self->tablepostfix;

	$self->{_issuer_certs} //= {};
	return $self->{_issuer_certs}->{$issuer} if defined($self->{_issuer_certs}->{$issuer});

	my $issuer_certs = [];

	my $issuer_cert_ids = $self->get_issuerids_for_issuer($issuer);
	if (scalar @$issuer_cert_ids) {
		$issuer_certs = CertReader::DB::Certificate::Manager->get_certificates_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => "select * from certificate_$postfix where id in (" . join(",", @$issuer_cert_ids) . ")",
		);
	}

	$self->{_issuer_certs}->{$issuer} = $issuer_certs;
	return $issuer_certs;
}

sub min_string {
	my ($a, $b) = @_;

	my @sorted = sort ($a, $b);
	return $sorted[0];
}

sub get_owner_ids_by_validitydate_for_issuer {
	# Note that there can be multiple owners due to different validity periods
	# of ca certificates in a cross-sign group
	my ($self, $issuer) = @_;

	my $owner_ids_by_validitydate = {};

	my $issuer_certs = $self->get_issuercerts_for_issuer($issuer);
	for my $issuer_cert (@$issuer_certs) {
		my $owner_id = $issuer_cert->get_owner_id;
		if (defined($owner_id)) {
			my @validity_dates = ();
			for my $childcert (@{$self->certs->{$issuer}}) {
				if ($childcert->is_valid($self->tablepostfix) != 0) {
					my $childcert_earliest_validitydate = $childcert->not_before;
					my $childcert_latest_validitydate = min_string($childcert->not_after, $issuer_cert->not_after);
					for my $validitydate (($childcert_earliest_validitydate, $childcert_latest_validitydate)) {
						if (!(grep {$_ eq $validitydate} @validity_dates)) {
							push(@validity_dates, $validitydate);
						}
					}
				}
			}
			for my $validitydate (@validity_dates) {
				$owner_ids_by_validitydate->{$validitydate} //= [];

				if (!(grep {$_ == $owner_id} @{$owner_ids_by_validitydate->{$validitydate}})) {
					push(@{$owner_ids_by_validitydate->{$validitydate}}, $owner_id);
				}
			}
		}
	}

	return $owner_ids_by_validitydate;
}

sub get_owner_chains_by_validitydate_for_issuer {
	# Note that there can be multiple owners due to different validity periods
	# of ca certificates in a cross-sign group
	my ($self, $issuer) = @_;
	my $postfix = $self->tablepostfix;

	$self->{_issuer_owners_by_validitydate} //= {};
	return $self->{_issuer_owners_by_validitydate}->{$issuer} if defined($self->{_issuer_owners_by_validitydate}->{$issuer});

	my $owner_ids_by_validitydate = $self->get_owner_ids_by_validitydate_for_issuer($issuer);
	my $no_owner_known = (scalar (keys %$owner_ids_by_validitydate)) == 0;
	if ($no_owner_known) {
		my $dummy_date = "yyyy-mm-ddd";
		my $warning_or_error_text = "Warning_invalid_cacert";

		# Check if any of the issuercerts is valid, in which case the issuer cert
		# misses an appropriate owner relation in the database which must be fixed
		my $valid_certs_ids = [];
		foreach (@{$self->get_issuercerts_for_issuer($issuer)}) {
			if ($_->is_valid($self->tablepostfix) != 0) {
				push @$valid_certs_ids, $_->id;
			}
		}
		if (scalar @$valid_certs_ids) {
			$warning_or_error_text = "Error_valid_cacert_without_owner (" . (join ",", @$valid_certs_ids) . ")";
		}

		return {$dummy_date => [[$warning_or_error_text]]};
	}

	my $owner_chains_by_validitydate = {};
	for my $validitydate (sort keys %$owner_ids_by_validitydate) {
		for my $owner_id (@{$owner_ids_by_validitydate->{$validitydate}}) {

			my $owners = [];
			while (1) {
				my $owner = CertReader::DB::CAactor->new(db => $self->db, 'id' => $owner_id);
				$owner->load();
				push @$owners, $owner->name;

				my $ca_relations = CertReader::DB::CArelation::Manager->get_carelations_from_sql(
					db => $self->db,
					inject_results => 1,
					sql => "select * from ca_relation_$postfix where ca_id = $owner_id and type = 'owned_by' and not_before <= '" . $validitydate . "' order by not_before desc limit 1;",
				);
				if (scalar @$ca_relations == 0) {
					last;
				}

				my $new_owner_id = @$ca_relations[0]->related_ca_id;
				if ($owner_id == $new_owner_id) {
					last;
				}
				$owner_id = $new_owner_id;
			}

			$owner_chains_by_validitydate->{$validitydate} //= [];
			push @{$owner_chains_by_validitydate->{$validitydate}}, $owners;
		}
	}

	$self->{_issuer_owners_by_validitydate}->{$issuer} = $owner_chains_by_validitydate;
	return $owner_chains_by_validitydate;
}

sub get_owners_for_issuer {
	my ($self, $issuer) = @_;

	my $owners = [];
	my $chains_by_validitydate = $self->get_owner_chains_by_validitydate_for_issuer($issuer);
	for my $validitydate (sort keys %$chains_by_validitydate) {
		for my $chain (@{$chains_by_validitydate->{$validitydate}}) {
			my $final_owner = $chain->[-1];
			if (!(grep {$_ eq $final_owner} @$owners)) {
				push @$owners, $final_owner;
			}
		}
	}

	return $owners;
}

sub get_owners_all_issuers {
	my $self = shift;

	my $owners = [];
	for my $issuer (keys %{$self->certs}) {
		my $owners_issuer = $self->get_owners_for_issuer($issuer);
		for my $owner_issuer (@$owners_issuer) {
			next if $owner_issuer eq "Warning_invalid_cacert";
			if (!(grep {$_ eq $owner_issuer} @$owners)) {
				push @$owners, $owner_issuer;
			}
		}
	}

	return $owners;
}

sub get_owners_all_certs {
	my $self = shift;

	my $owners = [];
	for my $issuer (keys %{$self->certs}) {
		for my $cert (@{$self->certs->{$issuer}}) {
			for my $cert_ownerchain (@{$cert->get_owner_chains($self->tablepostfix)}) {
				my $final_owner = $cert_ownerchain->[-1];
				next if $final_owner eq "Warning_invalid_cacert";
				if (!(grep {$_ eq $final_owner} @$owners)) {
					push @$owners, $final_owner;
				}
			}
		}
	}

	return $owners;
}

1;