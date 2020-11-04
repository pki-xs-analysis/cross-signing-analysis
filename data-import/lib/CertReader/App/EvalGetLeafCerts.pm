package CertReader::App::EvalGetLeafCerts;

# Verify all the certificates in our certificate table (without regard to the connection table).
# Mostly used by the notary

use forks; # ALWAYS LOAD AS FIRST MODULE, if possible
# Tell Forks::Queue to not play signal bomb
# Alternatively to disabling signals for queue signaling is to ensure a sufficiently
# Large stepsize such that not too many elements are withdrawn from the queue while
# a thread blocks, e.g., while waiting for response of the database. However, calculating
# an appropriate stepsize is quite system and situation dependent.
BEGIN { $ENV{FORKS_QUEUE_NOTIFY} = 0; } # Tell Forks::Queue to not play signal bomb
use Forks::Queue;
my $nworker = 5;
my $stepsize = 1000;  # Do not set too large, potential to exhaust memory
my $worker_stepsize = 1000000;
use Thread::Semaphore;
my $semaphore_table_write_cross_sign_candidate = Thread::Semaphore->new(1);

my $resultsdir_default = "./";

use 5.14.1;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use FileHandle;
use List::Util qw[min max];

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

has 'csc_id' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	documentation => "csc_id for which leaf certs should be found.",
);

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
	# TODO Actually, the corresponding verify_tree entries may be much more
	documentation => "Maximum number of (certificate-)entries requested from the database in one query. Influences memory usage. Default: $stepsize",
);

has 'worker_stepsize' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $worker_stepsize,
	documentation => "Number of certificates handled by a worker per batch. Influences number of output files. Default: $worker_stepsize",
);

has 'resultsdir' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	default => $resultsdir_default,
	documentation => "Select a parent directory that will be used to create the directory that will contain the results (default: .)",
);

has 'timestamp_start' => (
	is => 'ro',
	isa => 'Str',
	default => sub { POSIX::strftime("%F_%Hh-%Mm-%Ss%z", localtime()) },
	documentation => 'Timestamp at time of script startup',
);

sub run {
	my $self = shift;

	STDOUT->autoflush(1);
	STDERR->autoflush(1);

	say "Startup time: " . $self->timestamp_start;

	$self->{log_dir} = $self->resultsdir . "/" . $self->csc_id;
	if (not ($self->{log_dir} eq "./")) {
		say "Creating directory " . $self->{log_dir} . " for logs";
		croak("Could not create directory " . $self->{log_dir} . ": $!") if !mkdir($self->{log_dir});
	}

	my $log = $self->{log_dir} . "/log.txt";
	$self->{fh_log} = FileHandle->new($log, '>:encoding(UTF-8)');
	croak("Could not open $log") if !defined($self->{fh_log});
	$self->{fh_log}->autoflush(1);

	# my $log_results = $self->{log_dir} . "/results.txt";
	# $self->{fh_results} = FileHandle->new($log_results, '>:encoding(UTF-8)');
	# croak("Could not open $log") if !defined($self->{fh_results});
	# $self->{fh_results}->autoflush(1);


	say {$self->{fh_log}} "Startup time: " . $self->timestamp_start;

	say {$self->{fh_log}} "Cmd-Arguments:";
	say {$self->{fh_log}} "\tcsc_id: " . $self->csc_id;
	say {$self->{fh_log}} "\tnworker: " . $self->nworker;
	say {$self->{fh_log}} "\tworker_stepsize: " . $self->worker_stepsize;
	say {$self->{fh_log}} "\tstepsize: " . $self->stepsize;
	say {$self->{fh_log}} "\tresultsdir: " . $self->resultsdir;

	my $certs = $self->get_certs_for_csc_id($self->csc_id);
	my $roots = $self->get_roots_for_certs($certs, $self->{fh_log});

	my $stats = $self->run_eval();

	say "\n\nEval statistics: {";
	say {$self->{fh_log}} "\n\nEval statistics: {";
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
		} else {
			my $str = "\t\"$statistic\": " . $value . ",";
			say "$str";
			say {$self->{fh_log}} "$str";
		}
	}
	say "}";

	my $timestamp_end = POSIX::strftime("%F_%Hh-%Mm-%Ss%z", localtime());
	say "Finish time: $timestamp_end";
	say {$self->{fh_log}} "Finish; time: $timestamp_end";
	exit(0);
}


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


sub get_certs_for_csc_id {
	my $self = shift;
	my $csc_id = shift;
	my $postfix = $self->tablepostfix;

	my $sql = "select cert.* from csc_cert_$postfix as csc_cert join certificate_$postfix as cert on csc_cert.cert_id = cert.id where csc_id = " . $csc_id . ";";
	my $certs = CertReader::DB::Certificate::Manager->get_certificates_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => $sql,
	);

	return $certs;
}


sub get_roots_for_certs {
	my ($self, $certs, $log) = @_;

	my $roots = [];
	for my $cert (@$certs) {
		if ($cert->is_root_cert) {
			my $root = $cert->get_root_cert;
			push @{$roots}, $root;
			say $cert->id . " (root " . $root->id . ")" if defined($log);
			say {$log} $cert->id . " (root " . $root->id . ")" if defined($log);
		} else {
			say $cert->id if defined($log);
			say {$log} $cert->id if defined($log);
		}
	}
	return $roots;
}


sub run_eval() {
	my $self = shift;
	my $postfix = $self->tablepostfix;
	my $worker_batchsize = $self->worker_stepsize;
	my $batchsize = $self->stepsize;

	my $certid_max = CertReader::DB::Certificate::Manager->get_certificate_id_max($self->db, $self->tablepostfix);
	say "\tWe will iterate over a total of $certid_max certificates in batches of $batchsize (workers get batches of $worker_batchsize).";

	my $count_total = 0;
	my $count_self = 0;

	my $currid = 0;
	my $lastid = -1;
	my $maxid = $certid_max;

	my $queue = Forks::Queue->new( impl => 'Shmem' );
	my $workerbatch_id = 1;
	my $workerbatch_id_max = POSIX::ceil($maxid / $worker_batchsize);
	while( $lastid < $maxid ) {
		$lastid = min($currid + ($worker_batchsize - 1), $maxid);
		$queue->enqueue([$workerbatch_id, $workerbatch_id_max, $currid, $lastid]);
		$currid = $lastid + 1;
		$workerbatch_id += 1;
	}
	$queue->end();

	CertReader::App::EvalGetLeafCerts->disconnect_db_handlers($self);
	for ( 1 .. $self->nworker ) {
		threads->create( {'context' => 'list'}, \&run_eval_worker, $self, $queue );
	}

	my $stats = {};

	say "Waiting for worker to finish their work ...";
	foreach my $thr ( threads->list() ) {
		my ($ret, $w_stats) = $thr->join();
		if (!defined($ret)) {
			croak("error in run_eval_worker: terminated abnormally")
		}
		if ($ret != 0) {
			croak("error in run_eval_worker: $ret")
		}
		merge_stats($stats, $w_stats);
	}
	say "All worker finished";

	CertReader::App::EvalGetLeafCerts->reconnect_db_handlers($self);
	say "\tdone.";

	say "Finished Eval.";
	return $stats;
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


sub run_eval_worker() {
	my ($self, $queue) = @_;
	my $batchsize = $self->stepsize;
	my $postfix = $self->tablepostfix;
	my $tid = threads->self()->tid();
	my $prefix = "Worker $tid:";
	say "$prefix started.";

	my $log = $self->{log_dir} . "/log_worker${tid}.txt";
	$self->{fh_log} = FileHandle->new($log, '>:encoding(UTF-8)');
	croak("Could not open $log") if !defined($self->{fh_log});
	$self->{fh_log}->autoflush(1);

	my $w_stats = {
		'cert_cnt' => 0,
		'cert_cnt_xs-self' => 0,
	};


	my $certs = $self->get_certs_for_csc_id($self->csc_id);
	my $roots = $self->get_roots_for_certs($certs, undef);

	my %xs_certs_by_id = map { $_->id => 1 } @$certs;
	my %xs_roots_by_root_id = map { $_->id => $_ } @$roots;


	while ( my $in = $queue->dequeue() ) {
		my ($batch_id, $batch_id_max, $in_currid, $in_lastid) = @$in;
		say "\t" . localtime() . "    $prefix analyzing $in_currid - $in_lastid";

		my $batch_id_str = POSIX::sprintf("%0" . length($batch_id_max) . "d", $batch_id);
		my $w_log_base = "$self->{log_dir}/${batch_id_str}_${in_currid}-${in_lastid}";

		my $w_log = $w_log_base . "_results.txt";
		my $w_log_fh = FileHandle->new($w_log, '>:encoding(UTF-8)');
		croak("Could not open $w_log") if !defined($w_log_fh);
		$w_log_fh->autoflush(1);



		my $currid = $in_currid;
		my $lastid = -1;
		while( $lastid < $in_lastid ) {
			$lastid = min($currid + ($batchsize - 1), $in_lastid);

			my $cert_cnt = 0;
			my $cert_cnt_xsSelf = 0;

			my $sql = "select * from verify_tree_$postfix as vt where vt.certificate >= $currid and vt.certificate <= $lastid and (";
			my $first = 1;
			for my $root (@$roots) {
				if ($first) {
					$sql .= " vt.store = " . $root->id;
					$first = 0;
				} else {
					$sql .= " or vt.store = " . $root->id;
				}
			}
			for my $cert (@$certs) {
				if ($first) {
					$sql .= " vt.path ~ '*." . $cert->id . ".*'";
					$first = 0;
				} else {
					$sql .= " or vt.path ~ '*." . $cert->id . ".*'";
				}
			}
			$sql .= ") order by certificate asc;";
			my $vtiter = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
				db => $self->db,
				inject_results => 1,
				sql => $sql,
			);

			my $res = {};
			while (my $vt = $vtiter->next) {
				$res->{$vt->certificate} = [] if !defined($res->{$vt->certificate});
				push @{$res->{$vt->certificate}}, $vt;
			}

			for my $cert_id (sort keys %$res) {
				$cert_cnt += 1;
				$cert_cnt_xsSelf += 1 if exists($xs_certs_by_id{$cert_id});

				my $cert = CertReader::DB::Certificate->new(db => $self->db, id => $cert_id);
				$cert->load();

				my $vt_str = "";
				my %xs_parent_ids;  # store the ids of all certs in the xs group which make the current cert valid (incl. root)
				for my $vt (@{$res->{$cert_id}}) {
					$vt_str .= "    vt: " . $vt->store . ", " . $vt->path;

					# TODO The root is already included in the path
					# # check if the root is part of the xs
					# if (exists($xs_roots_by_root_id{$vt->store})) {
					# 	my $root = $xs_roots_by_root_id{$vt->store};
					# 	$xs_parent_ids{$root->certificate} = 1;
					# 	$vt_str .= ", (" . $root->certificate . "*)";
					# }

					# check if the path contains certs of the xs
					for my $path_cert_id (split /\./, $vt->path) {
						if (exists($xs_certs_by_id{$path_cert_id}) and !($path_cert_id eq $cert_id)) {
							$xs_parent_ids{$path_cert_id} = 1;
							$vt_str .= ", (" . $path_cert_id . ")";
						}
					}
					$vt_str .= "\n";
				}

				my $xs_parent_str = "(";
				$first = 1;
				for my $xs_parent_id (sort keys %xs_parent_ids) {
					if ($first) {
						$first = 0;
					} else {
						$xs_parent_str .= ",";
					}
					$xs_parent_str .= $xs_parent_id;
				}
				$xs_parent_str .= ")";

				my $subjectAltName = undef;
				my $openssl = $cert->openssl;
				if ($openssl->num_extensions > 0) {
					my $ext_subjectAltName = $openssl->extensions_by_name->{subjectAltName};
					$subjectAltName = $ext_subjectAltName->to_string if defined($ext_subjectAltName);
				}

				my $cert_ca = 0;
				$cert_ca = $cert->ca if $cert->ca;
				say {$w_log_fh} "cert: " . $cert->id . ", ca: " . $cert_ca . ", " . $cert->not_before . ", " . $cert->not_after . ", " . $cert->fingerprint_sha256 . ", xs_in_paths: " . $xs_parent_str;
				say {$w_log_fh} "    subject: " . $cert->subject;
				say {$w_log_fh} "    subjectAltName: " . $subjectAltName if defined($subjectAltName);
				say {$w_log_fh} $vt_str;
			}
			$w_stats->{'cert_cnt'} += $cert_cnt;
			$w_stats->{'cert_cnt_xsSelf'} += $cert_cnt_xsSelf;

			say "\t" . localtime() . "    $prefix $currid - $lastid: found $cert_cnt (w_total: " . $w_stats->{'cert_cnt'} . ", " . $w_stats->{'cert_cnt_xsSelf'} . " of the xs-group itself)";

			$currid = $lastid + 1;
		}


		undef $w_log_fh;  # automatically closes the file
	}

	say localtime() . "    $prefix finished.";
	return 0, $w_stats;
}


1;