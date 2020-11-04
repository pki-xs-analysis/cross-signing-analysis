package CertReader::App::VerifyCerts;

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
my $nsubworker = 1;
my $stepsize = 10000;

use 5.14.1;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use DateTime::Format::ISO8601;
use List::Util qw[min max];

use Moose;

use Crypt::OpenSSL::X509;
use Date::Parse;
use Date::Format;

# use Devel::Leak::Object qw{ GLOBAL_bless };

with 'CertReader::Base';
with 'CertReader::CA';
with 'CertReader::CertCache';

has 'mode' => (
	is => 'rw',
	isa => 'Str',
	required => 1,
	documentation => 'Verification mode. OpenSSLCAs, OpenSSLAll',
);

has 'limited_path_analysis' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'WARNING: For each root certificate, stop path search for a certificate as soon as one valid path has been found. This is not suitable when statements on all possible validation paths need to be taken. The verify_tree will not contain all possible paths from a given certificate to a given root. Even more, at a new invocation of the script, for a certificate that already is valid according to ANY root certificate, it will skip the certificate completely, and thus may even miss new paths that cause another root certificate to validate the certificate.',
);

has 'nworker' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $nworker,
	documentation => "Number of threads. Default: $nworker",
);

has 'nsubworker' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $nsubworker,
	documentation => "Number of subthreads that threads may create to assist their work. nsubworker < 2 means none. Default: $nsubworker",
);

has 'stepsize' => (
	is => 'rw',
	isa => 'Int',
	required => 1,
	default => $stepsize,
	documentation => "Maximum number of lines requested from the database in one query. Default: $stepsize",
);

has 'start_with_certid' => (
	is => 'rw',
	isa => 'Int',
	required => 0,
	default => 0,
	documentation => "Skip all certificates with id smaller than given. Usually only needed to resume work.",
);

has 'update_known_paths' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Check if the found known paths require an update. Only useful if verify_tree entries were created with old DB schema',
);

has 'full_revalidation' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Ignore the status information on performed validation and rerun everything not explicitly disabled by options.',
);

# TODO move to CA.pm
has 'skip_cachain_generation' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Assume that the table ca_chain already reflects the state with all current CA certificates.',
);

has 'do_not_restart_validation_on_new_cachain' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Ignore that an ca_chain added after start of the (partial or full) validation state requires a restart of the validation in favor of completing the current partial state first.',
);

has 'ignore_google_ct_precert_signing_certs' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Exclude certificates with the whose subject contains: Google Certificate Transparency (Precert Signing).',
);

has 'skip_notary_certs_not_valid_in_notary' => (
	is => 'rw',
	isa => 'Bool',
	required => 1,
	default => 0,
	documentation => 'Exclude certificates of the notary that do not have a valid path in the notary.',
);

has 'start_with_chainlen' => (
	is => 'rw',
	isa => 'Int',
	required => 0,
	default => 0,
	documentation => "Start with the given chain_len when searching verify_tree entries. WARNING: Can screw up the validation state if certs are considered which have not been validated up to chain_len already.",
);

my $attime_label_to_epoch = {
	'1970-01-01' => 0,
	'2018-07-01' => 1530403200,  # date -d "2018-07-01 00:00:00" --utc +%s
	'validity_any_day' => 0, # use the certificate validity period to try all suitable attimes
};
my $attime_epoch_to_label = {};
for my $label (keys %$attime_label_to_epoch) {
	my $epoch = $attime_label_to_epoch->{$label};
	$attime_epoch_to_label->{$epoch} = $label;
}
my $attime_label_default = "2018-07-01";
has 'attime_label' => (
	is => 'rw',
	isa => 'Str',
	documentation => "See --attime. Default if attime not defined: $attime_label_default. Currently defined labels: " . join(", ", keys %$attime_label_to_epoch) . ";",
);
has 'attime' => (
	is => 'rw',
	isa => 'Int',
	required => 0,
	documentation => "Perform validation checks using time specified by timestamp (in UNIX epoch) instead of current system time (see `man 1 openssl-verify`). Default see --attime_label.",
);

my $paths_new = 0;
my $paths_already_known = 0;
my $paths_updated = 0;

sub run {
	my $self = shift;

	if ($self->limited_path_analysis) {
		say "\n\n############\nWARNING: Using limited_path_analysis mode. See --help for its limitations!\n############\n";
		say "\n\n############\nWARNING: limited_path_analysis mode not thoroughly tested with validity information in separate table!\n############\n";
		croak("limited_path_analysis no longer supported, due to dropped support of valid bitmap");
	}

	if (defined($self->attime_label) and defined($self->attime)) {
		croak("Inconsistent attime_label and attime attributes. Try to only specify one.") if ($attime_label_to_epoch->{$self->attime_label} != $self->attime);
	} elsif (defined($self->attime_label)) {
		croak("Unknown attime for attime_label $self->{attime_label}. Adapt or add it.") if !defined($attime_label_to_epoch->{$self->attime_label});
		$self->attime($attime_label_to_epoch->{$self->attime_label});
	} elsif (defined($self->attime)) {
		croak("Unknown attime_label $self->{attime}. Adapt or add it.") if !defined($attime_epoch_to_label->{$self->attime});
		$self->attime_label($attime_epoch_to_label->{$self->attime});
	} else {
		$self->attime_label($attime_label_default);
		$self->attime($attime_label_to_epoch->{$self->attime_label});
	}
	my $attime_dt = DateTime->from_epoch( epoch => $self->attime);
	say "Checking validity of certificates using epoch $self->{attime} (label: $self->{attime_label}; iso8601: " . $attime_dt->iso8601() . ")";

	my $mode = lc($self->mode);

	# my $postfix = $self->tablepostfix;
	# say "Creating missing entries in certificate_validity_$postfix";
	# # # Ensure that the CertificateValidity for root stores is properly set
	# # my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
	# # 	db => $self->db,
	# # 	inject_results => 1,
	# # 	sql => "select * from certificate_$postfix where id in (select certificate from root_certs_$postfix) and id not in (select certificate from certificate_validity_$postfix where verify_attime = '$self->{attime_label}');",
	# # );
	# # while (my $root_cert = $certiter->next) {
	# # 	$root_cert->init_validity_if_not_exists($attime_dt);
	# # }
	# #
	# # Ensure that the validity system is up to date
	# my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator(db => $self->db);
	# while (my $cert = $certiter->next) {
	# 	$cert->init_validity_if_not_exists($attime_dt);
	# }

	if ( $mode eq 'nss' ) {
		croak("no nss");
		#$self->verifynss;
	} elsif ( $mode eq 'opensslcas' ) {
		$self->verifycas;
	} elsif ( $mode eq 'opensslall' ) {
		$self->verifyall;
	} else {
		croak('Invalid mode');
	}

	my $paths_total = $paths_new + $paths_already_known;
	say "Found $paths_total paths ($paths_already_known already known (thereof $paths_updated were updated); $paths_new new paths)";
	if (! $self->update_known_paths) {
		say "  Note: --update_known_paths was NOT enabled (default).";
	}

	exit(0);
}

=blob nss

# verify the current validity of all certificates using NSS
# we do not need a dedicated step for CAs and normal certificates like with openssl, because
# NSS determines all currently valid intermediates while polulating the intermediates.
sub verifynss {
	my $self = shift;

	if ( !defined($self->ca) ) {
		$self->ca(CertReader::CA->new( timestamp => time, dir =>$self->cadir ));
	}

	# first - populate intermediates
	$self->populate_intermediates;

	# ok, this does not strictly speaking belong here... but still, prevent me from damaging the live db
	croak("Do not run nss on live store") if ( $self->store <= 1 ) ;

	# second - select all certificates that are currently not marked as being valid...
	my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		# TODO speed up by only considering certificates that are valid at the current $self->attime
		sql => "SELECT * FROM certificate_".$self->tablepostfix." WHERE ( valid & B'".$self->generate_store_no($self->store)."' )::integer = 0;",
	);

	say "Starting processing...";

	while ( my $cert = $certiter->next ) {
		next if ($cert->valid($attime_dt)->bit_test($self->store));

		say "Trying to verify ".$cert->subject;

		my $nsscert;

		eval {
			$nsscert = Crypt::NSS::X509::Certificate->new($cert->der);
		} or do {
			say $@;
			say "OpenSSL subject of the certificate ".$cert->id." is: ".$cert->subject;

			Crypt::NSS::X509::dump_certificate_cache_info();

			next;
		};

		my $verify = $nsscert->verify_cert;

		if ( $nsscert->verify_cert == 1 ) {
			$cert->valid($attime_dt)->Bit_On($self->store);
			$cert->save;
		}

	}

}

=cut

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

sub epoch2str {
	my $epoch = shift;
	return time2str("%Y-%m-%d %H:%M:%S", $epoch, "UTC");
}

sub attime_try_any_day {
	my $self = shift;
	if ($self->attime_label eq 'validity_any_day') {
		return 1;
	}
	return 0;
}

sub get_vts {
	my ($self, $cert, $ts) = @_;
	my $verify_attime = epoch2str($ts);
	my $ret = {};

	# my $sql_query = "select * from verify_tree_$self->{tablepostfix} where certificate = $cert->{id} and verify_attime = '$verify_attime';";
	my $sql_query = "select * from verify_tree_$self->{tablepostfix} where certificate = $cert->{id}";
	if (! $self->attime_try_any_day) {
		$sql_query .= " and verify_attime = '$verify_attime'";
	}
	$sql_query .= ";";

	my $vtiter = CertReader::DB::VerifyTree::Manager->get_verifypaths_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => $sql_query,
	);

	while ( my $vt = $vtiter->next ) {
		$ret->{$vt->store} //= {};
		$ret->{$vt->store}->{$vt->path} = 1;
	}

	return $ret;
}

# verify the current validity of CA certificates
sub verifycas {
	my $self = shift;
	my $postfix = $self->tablepostfix;
	my $attime_dt = DateTime->from_epoch( epoch => $self->attime);

	say "Trying to verify roots...";

	$self->thorough(1);
	$self->populate_cas;

	if ($self->full_revalidation) {
		say "WARNING: Ignoring known validation information. This will significantly prolong the verification!";
		croak("Full revalidation currently not supported; TODO: Need to drop partial validation state");
	} else {
		say "Looking for date of latest ca_chain change...";
		# my $sql = "select * from ca_chain_$postfix where added_to_db = (select max(added_to_db) from ca_chain_$postfix) limit 1;";
		say "\tWARNING: Assuming that ca_chain with max(id) was added last";
		my $sql = "select * from ca_chain_$postfix where id = (select max(id) from ca_chain_$postfix) limit 1;";  # TODO assumes that ca_chains are not imported from somewhere else
		my $ca_chains = CertReader::DB::CaChain::Manager->get_cachains_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);
		$self->{'latest_ca_chain_update'} = $ca_chains->[0]->added_to_db;
		say "\t" . $self->{'latest_ca_chain_update'};
	}

	say "Looking for largest chain_len of ca_chains...";
	my $ca_chains_maxchainlen = CertReader::DB::CaChain::Manager->get_cachains_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "select * from ca_chain_$postfix where chain_len = (select max(chain_len) from ca_chain_$postfix) limit 1;",
	);
	$self->{'cachain_chainlen_max'} = $ca_chains_maxchainlen->[0]->chain_len;
	say "\t" . $self->{'cachain_chainlen_max'};

	say "Looking for certificates to be analyzed...";
	# To find all paths (and all roots) for a cert, we cannot skip certificates that are already valid due to some root cert(s)
	my $sql = "select * from certificate_$postfix where ca = 't' and selfsigned = 'f'";
	if ($self->ignore_google_ct_precert_signing_certs) {
		say "\tChosen option: Excluding certificates with subject-substring '%Google Certificate Transparency (Precert Signing)%'";
		$sql .= " and not (subject like '%Google Certificate Transparency (Precert Signing)%')";
	}
	if ($self->skip_notary_certs_not_valid_in_notary) {
		my $notary_certs_id_max = 225092753;
		say "\tChosen option: Excluding notary certificates that have not been valid in the notary (WARNING: hardcoded ID $notary_certs_id_max!)";
		$sql .= " and (id > $notary_certs_id_max or 0 < (select count(*) from verify_tree_" . $postfix . "_oldschema as vt where certificate_$postfix.id = vt.certificate limit 1))";
	}
	$sql .=  " order by id desc;";
	my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => $sql,
	);

	my @cert_ids;
	while ( my $cert = $certiter->next ) {
		push(@cert_ids, $cert->id)
	}

	say "Adding certs to queue for threads...";
	my $verifycas_queue = Forks::Queue->new( impl => 'Shmem' );
	my $chain_len = 0;
	if ($self->start_with_chainlen) {
		$chain_len = $self->start_with_chainlen;
		say "WARNING: Skipping all ca_chains with chain_len < $chain_len";
	}
	while ($chain_len <= $self->{'cachain_chainlen_max'}) {
		say "\tchain_len $chain_len";
		for my $cert_id (@cert_ids) {
			my $count = $verifycas_queue->enqueue( "$cert_id,$chain_len" );
			if ($count != 1) {
				croak("Could not add to queue");
			}
		}
		$chain_len += 1;
	}
	$verifycas_queue->end();

	CertReader::App::VerifyCerts->disconnect_db_handlers($self);

	for ( 1 .. $self->nworker ) {
		threads->create( {'context' => 'list'}, \&verifycas_worker, $self, $verifycas_queue );
	}

	say "Waiting for worker to finish their work ...";
	my $watchdog_timeout_seconds = 900;
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
	my $worker_errors = 0;
	foreach my $thr ( threads->list() ) {
		my ($w_p_new, $w_p_known, $w_p_updated) = $thr->join();
		if (defined($w_p_new) and defined($w_p_known) and defined($w_p_updated)) {
			$paths_new += $w_p_new;
			$paths_already_known += $w_p_known;
			$paths_updated += $w_p_updated;
		} else {
			$worker_errors += 1;
			say "WARNING: Worker stopped abnormally! (total of $worker_errors worker stopped erroneously)"
		}
	}
	say "All worker finished ($worker_errors worker encountered errors)";

	CertReader::App::VerifyCerts->reconnect_db_handlers($self);

}

sub verifycas_worker {
	my ($self, $verifycas_queue) = @_;
	my $postfix = $self->tablepostfix;
	my $prefix = "Worker " . threads->self()->tid() . ":";
	say "$prefix started.";

	CertReader::App::VerifyCerts->reconnect_db_handlers($self);

	my $cert_cnt = 0;
	while ( my $queue_out = $verifycas_queue->dequeue() ) {
		my ($cert_id, $chain_len) = split(/,/, $queue_out);
		my $cert_validation_state = CertReader::DB::ValidationStateCertificate->new(cert_id => $cert_id);
		$cert_validation_state->load(speculative => 1);
		if (defined $self->{'latest_ca_chain_update'}){
			if (defined $cert_validation_state->verified_at) {
				if (str2time($cert_validation_state->verified_at, "UTC") > str2time($self->{'latest_ca_chain_update'}, "UTC") or $self->do_not_restart_validation_on_new_cachain) {
					say "$prefix skipping CA cert $cert_id: already checked at $cert_validation_state->{verified_at} > " . $self->{'latest_ca_chain_update'};
					next;
				}
			}
			# not yet fully verified
			my $restart_partial_validation = 0;
			if (defined $cert_validation_state->partial_state_started_at) {
				if (str2time($cert_validation_state->partial_state_started_at, "UTC") <= str2time($self->{'latest_ca_chain_update'}, "UTC") and not $self->do_not_restart_validation_on_new_cachain) {
					# there was a ca_chain update after the start of the partial validation state, start from scratch
					say "$prefix Restarting validation for CA cert $cert_id: partial validation from " . $cert_validation_state->{partial_state_started_at} . " <= " . $self->{'latest_ca_chain_update'};
					$restart_partial_validation = 1;
				}
			} else {
				# partial validation has not started
				$restart_partial_validation = 1;
			}
			if ($restart_partial_validation) {
				if ($chain_len != 0) {
					croak("ERROR: Trying to restart validation with chain_len $chain_len != 0");
				}

				$cert_validation_state->partial_state_started_at(time2str("%Y-%m-%d %H:%M:%S", time, "UTC"));
				$cert_validation_state->partial_state_chainlen(undef);
				$cert_validation_state->partial_state_rid(undef);
				$cert_validation_state->partial_state_cachain(undef);
				$cert_validation_state->save;
			}

			if (defined $cert_validation_state->partial_state_chainlen) {
				if ($chain_len <= $cert_validation_state->partial_state_chainlen) {
					say "$prefix Skipping chain_len $chain_len for CA cert $cert_id";
					next;
				}
				if ($chain_len - 1 != $cert_validation_state->partial_state_chainlen) {
					my $err_partial_state_chainlen_value = $cert_validation_state->partial_state_chainlen;
					croak("ERROR: Trying to verify cert $cert_id for chain_len $chain_len while partial_state_chainlen is $err_partial_state_chainlen_value");
				}
			} else {
				if ($chain_len != 0) {
					croak("ERROR: Trying to verify cert $cert_id for chain_len $chain_len != 0 while partial_state_chainlen is undefined");
				}
			}
		}

		my $cert = CertReader::DB::Certificate->new(id => $cert_id);
		$cert->load();
		my $paths_new_currround_start = $paths_new;
		my $paths_already_known_currround_start = $paths_already_known;
		my $paths_updated_currround_start = $paths_updated;
		say "$prefix analyzing CA cert $cert->{id}, chain_len $chain_len -- (already checked $cert_cnt certs)";  # if ($cert_cnt % 100 == 0);

		my $ts = $self->attime;

		my $write_to_db = 1;
		$self->validateChain($cert, $ts, $prefix, $write_to_db, $chain_len, $cert_validation_state);
		# my %res = $self->validateChain($cert, $ts, $prefix);

		# my $vts = $self->get_vts($cert, $ts) if (scalar keys %res);
		# for my $rid ( keys %res ) {
		# 	for my $chain (@{$res{$rid}}) {
		# 		# TODO uses the wrong $ts if $self->attime_try_any_day is true.
		# 		# As validateChain changes the $ts for each chain until a valid
		# 		# one is found, we would have to return the corresponding $ts.
		# 		# For now we are fine with them having epoch 0.
		# 		# TODO: The statement "changes the $ts for each chain until a
		# 		# valid one is found" is not correct. We check the first day of
		# 		# the validity period of all certs in the chain (incl. root & leaf)
		# 		$self->savetree($cert, $rid, $chain, $vts, $ts);
		# 	}
		# }
		# # $cert->save;

		my $p_round_new = $paths_new - $paths_new_currround_start;
		my $p_round_known = $paths_already_known - $paths_already_known_currround_start;
		my $p_round_updated = $paths_updated - $paths_updated_currround_start;
		$cert_cnt += 1;
		say "$prefix Finished cert " . $cert->id . " (chain_len $chain_len) ... Found $p_round_new new and $p_round_known known paths (updated: $p_round_updated)" if $p_round_new or $p_round_known;

		if ($chain_len == $self->{'cachain_chainlen_max'}) {
			# fully done
			$cert_validation_state->verified_at( $cert_validation_state->partial_state_started_at );
			$cert_validation_state->partial_state_started_at(undef);
			$cert_validation_state->partial_state_chainlen(undef);
			$cert_validation_state->partial_state_rid(undef);
			$cert_validation_state->partial_state_cachain(undef);
			$cert_validation_state->save;
		} else {
			# chain_len finished
			$cert_validation_state->partial_state_chainlen($chain_len);
			$cert_validation_state->partial_state_rid(undef);
			$cert_validation_state->partial_state_cachain(undef);
			$cert_validation_state->save;
		}
	}

	say "$prefix finished. Found a total of $paths_new new and $paths_already_known known paths (updated: $paths_updated)";
	return $paths_new, $paths_already_known, $paths_updated;
}

# verify all non-ca certificates
sub verifyall {
	my ( $self ) = @_;
	my $postfix = $self->tablepostfix;
	my $attime_dt = DateTime->from_epoch( epoch => $self->attime);
	my $stepsize = $self->stepsize;

	my $currid = 0;
	my $lastid = -1;

	if ($self->start_with_certid) {
		$currid = $self->start_with_certid;
	}

	$self->populate_cas;

	my $certid_max = CertReader::DB::Certificate::Manager->get_certificate_id_max($self->db, $postfix);
	say "We will analyze a total of $certid_max certificates.";

	my $verifyall_queue = Forks::Queue->new( impl => 'Shmem' );

	while( $lastid < $certid_max ) {
		$lastid = min($currid + ($stepsize - 1), $certid_max);
		$verifyall_queue->enqueue([$currid, $lastid]);
		$currid = $lastid + 1;
	}
	$verifyall_queue->end();

	CertReader::App::VerifyCerts->disconnect_db_handlers($self);
	for ( 1 .. $self->nworker ) {
		threads->create( {'context' => 'list'}, \&verifyall_worker, $self, $verifyall_queue );
	}

	say "Waiting for worker to finish their work ...";
	my $watchdog_timeout_seconds = 900;
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
	my $worker_errors = 0;
	foreach my $thr ( threads->list() ) {
		my ($w_p_new, $w_p_known, $w_p_updated) = $thr->join();
		if (defined($w_p_new) and defined($w_p_known) and defined($w_p_updated)) {
			$paths_new += $w_p_new;
			$paths_already_known += $w_p_known;
			$paths_updated += $w_p_updated;
		} else {
			$worker_errors += 1;
			say "WARNING: Worker stopped abnormally! (total of $worker_errors worker stopped erroneously)"
		}
	}
	say "All worker finished ($worker_errors worker encountered errors)";

	CertReader::App::VerifyCerts->reconnect_db_handlers($self);
}

sub verifyall_worker {
	my ($self, $verifyall_queue) = @_;
	my $postfix = $self->tablepostfix;
	my $prefix = "Worker " . threads->self()->tid() . ":";
	say "$prefix started.";

	CertReader::App::VerifyCerts->reconnect_db_handlers($self);

	while ( my $in = $verifyall_queue->dequeue() ) {
		my $paths_new_currround_start = $paths_new;
		my $paths_already_known_currround_start = $paths_already_known;
		my $paths_updated_currround_start = $paths_updated;
		my ($currid, $lastid) = @$in;
		say "$prefix analyzing certs $currid - $lastid";
		# my $wait = time + 10; while(time < $wait){ sleep 1; } next; # TODO remove

		# TODO why don't we restrict to non-CA certs only?
		# TODO Speed up by excluding certs not valid during attime
		# and not_before < $attime_postgresformatted AND not_after > $attime_postgresformatted
		my $sql = "select * from certificate_$postfix where selfsigned = 'f' and id >= $currid and id <= $lastid";
		if ($self->ignore_google_ct_precert_signing_certs) {
			say "\tChosen option: Excluding certificates with subject-substring '%Google Certificate Transparency (Precert Signing)%'";
			$sql .= " and not (subject like '%Google Certificate Transparency (Precert Signing)%')";
		}
		if ($self->skip_notary_certs_not_valid_in_notary) {
			my $notary_certs_id_max = 225092753;
			say "\tChosen option: Excluding notary certificates that have not been valid in the notary (WARNING: hardcoded ID $notary_certs_id_max!)";
			$sql .= " and (id > $notary_certs_id_max or 0 < (select count(*) from verify_tree_" . $postfix . "_oldschema as vt where certificate_$postfix.id = vt.certificate limit 1))";
		}
		$sql .= " order by id asc;";
		my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql,
		);

		while ( my $cert = $certiter->next ) {
			my $ts = $self->attime;

			my $cert_validation_state = CertReader::DB::ValidationStateCertificate->new(cert_id => $cert->id);
			if ($cert_validation_state->load(speculative => 1)) {
				if (defined $self->{'latest_ca_chain_update'}){
					if (str2time($cert_validation_state->verified_at, "UTC") > str2time($self->{'latest_ca_chain_update'}, "UTC") or $self->do_not_restart_validation_on_new_cachain) {
						say "$prefix skipping cert " . $cert->id . ": already checked at $cert_validation_state->{verified_at} > " . $self->{'latest_ca_chain_update'};
						next;
					}
				}
			}
			# TODO So we are going to verify this cert. However, to speed up the validation, we should skip chains that have been added before $cert_validation_state->verified_at
			my $validation_time_start = time;

			my $write_to_db = 1;
			$self->validateChain($cert, $ts, $prefix, $write_to_db);
			# my %res = $self->validateChain($cert, $ts, $prefix);

			# my $vts = $self->get_vts($cert, $ts) if (scalar keys %res);
			# for my $rid ( keys %res ) {
			# 	for my $chain (@{$res{$rid}}) {
			# 		# TODO uses the wrong $ts if $self->attime_try_any_day is true.
			# 		# As validateChain changes the $ts for each chain until a valid
			# 		# one is found, we would have to return the corresponding $ts.
			# 		# For now we are fine with them having epoch 0.
			# 		# TODO: The statement "changes the $ts for each chain until a
			# 		# valid one is found" is not correct. We check the first day of
			# 		# the validity period of all certs in the chain (incl. root & leaf)
			# 		$self->savetree($cert, $rid, $chain, $vts, $ts);
			# 	}
			# }
			# # $cert->save;

			# TODO required in case of threading???
			# $self->certcache( {} );

			$cert_validation_state->verified_at(time2str("%Y-%m-%d %H:%M:%S", $validation_time_start, "UTC"));
			$cert_validation_state->save;
		}

		my $p_round_new = $paths_new - $paths_new_currround_start;
		my $p_round_known = $paths_already_known - $paths_already_known_currround_start;
		my $p_round_updated = $paths_updated - $paths_updated_currround_start;
		say "$prefix Finished certs $currid - $lastid ... Found $p_round_new new and $p_round_known known paths (updated: $p_round_updated)";
	}
	say "$prefix finished. Found a total of $paths_new new and $paths_already_known known paths (updated: $paths_updated)";
	return $paths_new, $paths_already_known, $paths_updated;
}

sub savetree {
	# Not thread safe: Ensure that different threads process distinct $cert or $rid
	my ($self, $cert, $rid, $validchain, $vts, $ts) = @_;
	my $verify_attime = epoch2str($ts);

	my $path = $validchain->get_path;
	my $can_issue_based_on_pathlen = undef;
	if ($cert->ca) {
		$can_issue_based_on_pathlen = $validchain->can_issue_based_on_pathlen;
	}
	my $chain_not_before = $validchain->not_before;
	my $chain_not_after = $validchain->not_after;


	# croak("Missing verify_tree_data") if !defined($vts);
	my $already_known = 0;
	my $known_vt;
	if (defined $vts) {
		if (defined($vts->{$rid})) {
			if (defined($vts->{$rid}->{$path}) and $vts->{$rid}->{$path}) {
				$already_known = 1;

				# load certificate if needed
				if ($self->update_known_paths) {
					my $sql_query = "select * from verify_tree_$self->{tablepostfix} where certificate = $cert->{id} and store = $rid and path = '$path'";
					if (! $self->attime_try_any_day) {
						$sql_query .= " and verify_attime = '$verify_attime'";
					}
					my $known_vts = CertReader::DB::VerifyTree::Manager->get_verifypaths_from_sql(
						db => $self->db,
						inject_results => 1,
						sql => $sql_query,
					);
					$known_vt = ${$known_vts}[0];

					my $known_vts_cnt = scalar @$known_vts;
					if ($known_vts_cnt != 1) {
						warn "Expected 1 known verify_tree entry, got $known_vts_cnt (rid: $rid, path: $path, cert: $cert->{id}";
					}
				}
			}
		}
	} else {
		# my $sql_query = "select * from verify_tree_$self->{tablepostfix} where certificate = $cert->{id} and store = $rid and path = '$path'";
		my $sql_query = "select * from verify_tree_$self->{tablepostfix} where certificate = $cert->{id} and ca_chain_id = $validchain->{ca_chain_id}";
		if (! $self->attime_try_any_day) {
			$sql_query .= " and verify_attime = '$verify_attime'";
		}
		my $known_vts = CertReader::DB::VerifyTree::Manager->get_verifypaths_from_sql(
			db => $self->db,
			inject_results => 1,
			sql => $sql_query,
		);
		if (scalar @$known_vts) {
			$already_known = 1;
			$known_vt = ${$known_vts}[0];

			my $known_vts_cnt = scalar @$known_vts;
			if ($known_vts_cnt != 1) {
				warn "Expected 1 known verify_tree entry, got $known_vts_cnt (rid: $rid, path: $path, cert: $cert->{id}";
			}
		}
	}

	if ($already_known) {
			if ($self->update_known_paths) {

				my $update_validity = 0;
				if (defined($known_vt->not_before)) {
					$update_validity = 1 if str2time($known_vt->not_before, "GMT") != str2time($chain_not_before, "GMT");
				} else {
					if (defined $chain_not_before) {
						$update_validity = 1;
					} else {
						warn "unkown not_before (rid: $rid, path: $path, cert: $cert->{id}";
					}
				}
				if (defined($known_vt->not_after)) {
					$update_validity = 1 if str2time($known_vt->not_after, "GMT") != str2time($chain_not_after, "GMT");
				} else {
					if (defined $chain_not_after) {
						$update_validity = 1;
					} else {
						warn "unkown not_after (rid: $rid, path: $path, cert: $cert->{id}";
					}
				}

				my $update_pathlen_allows_issuance = 0;
				if (defined $can_issue_based_on_pathlen) {
					if (defined $known_vt->pathlen_allows_issuance) {
						if ($known_vt->pathlen_allows_issuance != $can_issue_based_on_pathlen) {
							$update_pathlen_allows_issuance = 1;
						}
					} else {
						$update_pathlen_allows_issuance = 1;
					}
				}

				if ($update_validity or $update_pathlen_allows_issuance) {
					# # CertReader::DB::VerifyTree lacks a primary key, thus we cannot use save
					# # see https://metacpan.org/pod/Rose::DB::Object
					# # TODO maybe introduce bigserial for verify_tree?
					$known_vt->not_before($chain_not_before);
					$known_vt->not_after($chain_not_after);
					$known_vt->pathlen_allows_issuance($can_issue_based_on_pathlen);
					$known_vt->save;

					# my $updated_cnt = CertReader::DB::VerifyTree::Manager->update_verifytrees(
					# 	set =>
					# 	{
					# 		not_before => $chain_not_before,
					# 		not_after => $chain_not_after,
					# 		pathlen_allows_issuance => $can_issue_based_on_pathlen,
					# 	},
					# 	where =>
					# 	[
					# 		certificate => $cert->id,
					# 		store => $rid,
					# 		path => $path,
					# 	]
					# );
					# if ($updated_cnt != 1) {
					# 	warn "Expected to update 1 verify_tree entry, but updated $updated_cnt";
					# }

					$paths_updated += 1;
				}
			}
	}

	if (!$already_known) {
		my $node = CertReader::DB::VerifyTree->new(
			certificate => $cert->id,
			store => $rid,
			ca_chain_id => $validchain->ca_chain_id,
			not_before => $chain_not_before,
			not_after => $chain_not_after,
			pathlen_allows_issuance => $can_issue_based_on_pathlen,
		);
		$node->save;
		$paths_new += 1;
	} else {
		$paths_already_known += 1;
	}
};

1;
