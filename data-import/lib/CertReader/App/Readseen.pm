package CertReader::App::Readseen;

# read the seen table for the notary.

use 5.14.1;
use strict;
use warnings;

use Carp;
use Bro::Log::Parse;
use List::Util qw/uniq pairs/;
use List::MoreUtils qw/zip/;
use Time::Local;
use Math::BigInt only => 'GMP';
use autodie;

use Moose;

with 'CertReader::Base';

use CertReader::Consts qw/%tls_versions %tls_ciphers/;

use Digest::SHA1  qw(sha1_hex);
use Data::Dumper;
use Pg::hstore;
use YAML::XS 'DumpFile';

has 'seencache' => (
	is => 'rw',
	isa => 'HashRef',
	default => sub { {} },
);

has 'writecache' => (
	is => 'rw',
	isa => 'HashRef',
	default => sub { {} },
);

has 'disableseenfull' => (
	is => 'rw',
	isa => 'Bool',
	required => '0',
	default => 0,
	documentation => "Disable populate seen_full (disable to make things quicker)"
);

has 'nodb' => (
	is => 'rw',
	isa => 'Bool',
	required => '0',
	default => 0,
	documentation => "Disable database access / writing for statistics"
);

has 'fileextension' => (
	is => 'rw',
	isa => 'Str',
	required => '0',
	default => '.statistics',
	documentation => "File extension used for statistic files"
);

has 'ignorenonestablished' => (
	is => 'rw',
	isa => 'Bool',
	required => '0',
	default => 0,
	documentation => "Do not import non-established connections"
);

has 'interestingsignaturesfile' => (
	is => 'rw',
	isa => 'Str',
	required => '0',
	documentation => "A file of interesting signatures where, when encountered, matching lines will be output to fileextension.interesting"
);

my %stats;
# This is kind of evil - but it makes the list of statistics extendable
BEGIN{
@CertReader::App::Readseen::stat_list = qw/all_ciphers https_ciphers https_withcert_ciphers https_withcertsni_ciphers smtp_ciphers smtp_withcert_ciphers smtp_withcertsni_ciphers versions dh_param_sizes point_formats client_curves curves client_alpns server_alpns client_exts server_exts client_ciphers
client_versions supported_versions psk_key_exchange_modes client_ciphers_all client_extensions_all client_ciphers_and_extensions_all
tls_signature ticket_lifetimes server_supported_version selected_version/;
eval "use vars(qw/".join(" ", map { "%".$_ } @CertReader::App::Readseen::stat_list)."/);";
}
our @stat_list;

my @grease_list = (0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa, 2570);
my %grease = map { $_ => 1 } @grease_list;

my %tls_signature_sniips;
my %interestingsignatures;
my $interestingsignaturesfh;
my $interestingsignaturesfn;

my $errcount = 0;

sub getLine {
	my $parse = shift;
	my $out;
	if ( $errcount >= 3 ) {
		croak("Error count too high, exiting");
	}
	eval {
		$out = $parse->getLine();
		$errcount = 0;
		1;
		} or do {
		return undef if ( ! $@ );
		say "Error while trying: $@";
		say "Trying to redo";
		$errcount++;
		};
	return $out;
}

sub add_to_hash {
	my ($f, $name, $hash) = @_;

	if ( defined($$f{$name}) ) {
		my @arr;
		if ( ref($$f{$name}) eq "ARRAY" ) {
			@arr = @{$$f{$name}};
		} else {
			@arr = split /,/, $$f{$name};
		}
		for my $entry (@arr) {
			$hash->{$entry}++;
		}
	}
}

sub add_concat_to_hash {
	my ($f, $name, $hash) = @_;
	if ( defined($$f{$name}) && $$f{$name} ne '' && $$f{$name} ne '-' ) {
		if ( ref($$f{$name}) eq "ARRAY" ) {
			$$f{$name} = join(',', @{$$f{$name}});
		}
		$hash->{$$f{$name}}++;
	}
}

sub add_arr_to_hash {
	my ($hash, $arr) = @_;
	for my $i (@$arr) {
		$hash->{$i}++;
	}
}

sub countline {
	my ($self, $f, $line) = @_;

	# skip the host at Site 12 that does all the trading stuff with RC4 - not normal traffic...
	return if ( defined($$f{orig_resp_hash}) && $$f{orig_resp_hash} eq '6eb7f6a4efcd2a4275f33b09f408344ede811130' );

	# hopefully we will have at least one correct timestamp in this file...
	my $ts = $$f{ts};
	unless ( $ts > 1577836800 || $ts < 1293840000 ) {
		$stats{'begin_time'} //= $ts;
		$stats{'end_time'} = $ts;
	}

	$stats{'all_lines'}++;
	if ( (!defined($$f{version})) || (!defined($$f{cipher})) || ( $$f{version} =~ /unknown/ ) ) {
		$stats{'invalid_version'}++;
		return;
	}
	if ( defined($$f{packet_loss}) && $$f{packet_loss} ne 'F' && $$f{packet_loss} ne '0' ) { # some really old files predate the packet_loss definition - we just skip over those too.
		$stats{'packet_loss'}++;
#		return;
	}

	# For the paper - ignore all nonestablished connections, at least for ICSI.
	if ( defined($$f{ssl_established}) && $$f{ssl_established} eq "T" ) {
		$stats{'established'}++;
	} else {
		return if ( $self->ignorenonestablished );
	}

	add_to_hash($f, 'client_ciphers', \%client_ciphers);
	add_to_hash($f, 'ssl_server_exts', \%server_exts);
	add_to_hash($f, 'ssl_client_exts', \%client_exts);

	$dh_param_sizes{$$f{dh_param_size}}++ if ( defined($$f{dh_param_size}) && $$f{dh_param_size} ne '' && $$f{dh_param_size} ne '-' );
	$curves{$$f{curve}}++ if ( defined($$f{curve}) && $$f{curve} ne '' && $$f{curve} ne '-' );
	# just concatenate ALP's. On the one hand, this is a bit icky, because we don't have
	# easy per-alpn-statistics. On the other hand, this enables us to easily track how
	# many different combinations we see - and there should (hopefully) not be too many
	# of them.
	add_concat_to_hash($f, 'orig_alpn', \%client_alpns);
	add_concat_to_hash($f, 'resp_alpn', \%server_alpns);
	add_concat_to_hash($f, 'client_curves', \%client_curves);
	add_concat_to_hash($f, 'point_formats', \%point_formats);
	add_concat_to_hash($f, 'supported_versions', \%supported_versions);
	add_concat_to_hash($f, 'psk_key_exchange_modes', \%psk_key_exchange_modes);

	unless ( $self->nodb ) {
		my @servercerts = ();
		if ( defined($$f{server_certs}) ) {
			@servercerts = split(/,/, $$f{server_certs});
		}

		for my $currcert (@servercerts) {
			if ( defined($self->writecache->{$currcert.$$f{server_p}}) ) {
				next;
			}

			$self->writecache->{$currcert.$$f{server_p}} = 1;
			$self->db->dbh->do("INSERT INTO certs_ports (certificate_sha1, certificate_port) VALUES ('$currcert', ".$$f{server_p}.") ON CONFLICT (certificate_sha1, certificate_port) DO NOTHING;");
		}
	}

	my $has_grease = 0;
	if ( defined($f->{client_ciphers}) ) {
		$f->{client_ciphers} = join(',', grep { if ( defined($grease{$_}) ) { $has_grease=1; 0 } else { 1 } } split(/,/, $f->{client_ciphers}) );
		$f->{client_ciphers}.=",GREASE" if ( $has_grease );
	}

	$has_grease = 0;
	if ( defined($f->{ssl_client_exts}) ) {
		$f->{ssl_client_exts} = join(',', grep { if ( defined($grease{$_}) ) { $has_grease=1; 0 } else { 1 } } split(/,/, $f->{ssl_client_exts}) );
		$f->{ssl_client_exts}.=",GREASE" if ( $has_grease );
	}

	add_concat_to_hash($f, 'client_ciphers', \%client_ciphers_all);
	add_concat_to_hash($f, 'ssl_client_exts', \%client_extensions_all);
	# manually concatenate ciphers and extensions
	if ( defined($$f{ssl_client_exts}) && defined($$f{client_ciphers}) ) {
		my $concat = $$f{client_ciphers}.";".$$f{ssl_client_exts};
		$client_ciphers_and_extensions_all{$concat}++;
	}
	# manually create a TLS signature by concatenating
	# version_num, client_ciphers, ssl_client_exts,client_curves,point_formats
	if ( defined($f->{client_ciphers}) ) {
		my $curves;
		if ( exists($f->{client_curves}) ) {
			if ( defined($f->{client_curves}) ) {
				$has_grease = 0;
				$f->{client_curves} = join(',', grep { if ( defined($grease{$_}) ) { $has_grease=1; 0 } else { 1 } } split(/,/, $f->{client_curves}) );
				$f->{client_curves}.=",GREASE" if ( $has_grease );
				$curves = $f->{client_curves};
			} else {
				$curves = "";
			}
		}	else {
				$curves = "!";
		}
		my $point_formats;
		if ( exists($f->{point_formats}) ) {
			if ( defined($f->{point_formats}) ) {
				$point_formats = $f->{point_formats};
			} else {
				$point_formats = "";
			}
		}	else {
				$point_formats = "!";
		}
		if ( defined($f->{ticket_lifetime_hint}) ) {
			$ticket_lifetimes{$f->{ticket_lifetime_hint}}++;
		}
		if ( defined($f->{server_supported_version}) ) {
			$server_supported_version{$f->{server_supported_version}}++;
		}
		my $cex = $$f{ssl_client_exts};
		$cex //= "";
		my $tls_sign_concat = (defined($f->{version_num}) ? $f->{version_num} : $f->{version}).";".$$f{client_ciphers}.";".$cex.";".$curves.";".$point_formats;
		$tls_signature{$tls_sign_concat}++;

		# Ok, now things get a bit complicated. Let's calculate the actual versions that were used.
		# Which we will store in selected_version. If server_supported_version is present, that's it.
		# If it is not, if the extension is present it is an unknown TLS 1.3 connection. Otherwise
		# It is the version given in the server hello. Easy, right?
		{
			my $resultversion;
			if ( defined($f->{server_supported_version}) ) {
				$resultversion = $f->{server_supported_version};
			} else {
				my %sexts;
				add_to_hash($f, 'ssl_server_exts', \%sexts);
				if ( defined($sexts{43}) ) {
					$resultversion = "TLSv13-unknown";
				} elsif ( defined($f->{version_num}) ) {
					$resultversion = $f->{version_num};
				} else {
					$resultversion = $f->{version};
				}
			}
			$selected_version{$resultversion}++;
		}

		if ( defined($$f{sni}) ) {
			$tls_signature_sniips{$tls_sign_concat}{snis}{$$f{sni}}++;
		}
		$tls_signature_sniips{$tls_sign_concat}{ips}{$$f{server}}++;
		$tls_signature_sniips{$tls_sign_concat}{connections}++;
		if ( !defined($tls_signature_sniips{$tls_sign_concat}{duration}) ) {
			$tls_signature_sniips{$tls_sign_concat}{duration} = Math::BigInt->new(0);
			$tls_signature_sniips{$tls_sign_concat}{client_bytes} = Math::BigInt->new(0);
			$tls_signature_sniips{$tls_sign_concat}{server_bytes} = Math::BigInt->new(0);
		}
		if ( !defined($f->{conn_duration}) ) {
			$f->{conn_duration} = 0;
		}
		$tls_signature_sniips{$tls_sign_concat}{duration}->badd(int($f->{conn_duration}*1000));
		$tls_signature_sniips{$tls_sign_concat}{client_bytes}->badd($f->{client_bytes});
		$tls_signature_sniips{$tls_sign_concat}{server_bytes}->badd($f->{server_bytes});

		my $filtersignature = $$f{client_ciphers}.";".$cex.";".$curves.";".$point_formats;
		$filtersignature =~ y/!//d;
		if ( defined($interestingsignatures{$filtersignature}) ) {
			if ( !defined($interestingsignaturesfh) ) {
				open($interestingsignaturesfh, ">", $interestingsignaturesfn);
			}
			say $interestingsignaturesfh $line;
		}
	}

	$stats{resumed}++ if ( defined($$f{resumed}) && $$f{resumed} eq 'T');
	$client_versions{$$f{client_version}}++ if ( defined($$f{client_version}) && $$f{client_version} ne '' && $$f{client_version} ne '-' );

	$stats{stapled_ocsp}++ if ( defined($$f{stapled_ocsp}) && $$f{stapled_ocsp} ne '-' && $$f{stapled_ocsp} > 0 );

	$stats{'all_ports'}++;
	$all_ciphers{$$f{'cipher'}}++;
	$versions{$$f{version}}++;
	croak("No server port") unless defined($$f{server_p});
	if ( $$f{server_p} == 443) {
		$stats{'https_port'}++;
		$https_ciphers{$$f{'cipher'}}++;
		$stats{'https_with_certs'}++ if defined($$f{server_certs});
		$https_withcert_ciphers{$$f{'cipher'}}++ if defined($$f{server_certs});;
		$stats{'https_with_sni'}++ if defined($$f{sni});
		$stats{'https_with_cert_and_sni'}++ if (defined($$f{server_certs}) && defined($$f{sni}) );
		$https_withcertsni_ciphers{$$f{'cipher'}}++ if (defined($$f{server_certs}) && defined($$f{sni}) );
		$stats{https_resumed}++ if ( defined($$f{resumed}) && $$f{resumed} eq 'T');
	}
	if ( $$f{server_p} == 25) {
		$stats{'smtp_port'}++;
		$smtp_ciphers{$$f{'cipher'}}++;
		$stats{'smtp_with_certs'}++ if defined($$f{server_certs});
		$smtp_withcert_ciphers{$$f{'cipher'}}++ if defined($$f{server_certs});;
		$stats{'smtp_with_sni'}++ if defined($$f{sni});
		$stats{'smtp_with_cert_and_sni'}++ if (defined($$f{server_certs}) && defined($$f{sni}) );
		$smtp_withcertsni_ciphers{$$f{'cipher'}}++ if (defined($$f{server_certs}) && defined($$f{sni}) );
		$stats{smtp_resumed}++ if ( defined($$f{resumed}) && $$f{resumed} eq 'T');
	}

	$stats{'with_certs'}++ if defined($$f{server_certs});
	$stats{'with_sni'}++ if defined($$f{sni});

	return unless ( defined($$f{server_certs}) && defined($$f{sni}) );

	$stats{'with_cert_and_sni'}++;
}

# This probably takes up a quite big chunk of processing time.
sub seenstats {
	my ($self, $f) = @_;

	my $ts = $$f{"ts"};
	my $postfix = $self->tablepostfix;

	my $full_hash_chain_sorted;
	my @servercerts = ( );
	if ( defined($$f{server_certs})  ) {
		@servercerts = split /,/, $$f{server_certs};
		$full_hash_chain_sorted = sha1_hex(join(",", sort(@servercerts)));
	}

	my $missing = 0;
	open (my $errlog, ">>errlog");

	my @certs;
	for my $cert_hash ( @servercerts ) {
		if ( defined($self->seencache->{$cert_hash}) ) {
			if ( $self->seencache->{$cert_hash} == -1 ) {
				$missing = 1;
				next;
			}

			push (@certs, $self->seencache->{$cert_hash});
			next;
		}

		my $key = 'fingerprint_sha1';
		$key = 'cert_hash' if ( length($cert_hash) == 32 );
		my $test = CertReader::DB::Certificate->new(db => $self->db, $key => $cert_hash);

		unless ( $test->load(use_key => $key, speculative => 1) ) {
			$self->seencache->{$cert_hash} = -1;
			$missing = 1;
			say $errlog "Certificate $cert_hash not found";
			next;
		}

		next if ( $test->gridtor ); # we do not want grid or tor-certs.
		push (@certs, $test->id);

		$self->seencache->{$cert_hash} = $test->id;
		croak() unless($ts > 1000);

		$self->db->dbh->do("INSERT INTO seen_$postfix (certificate_id, time) VALUES (".$test->id.", date_trunc('day', timestamp 'epoch' + $ts * interval '1 second')) ON CONFLICT (certificate_id, time) DO NOTHING;");
	}

	# ok, this one apparently had no grid or tor certs. That we know of.
	# Let's write it in the chains list
	if ( ($missing == 0 ) && ((scalar @certs) > 0) ) {

		$stats{'non_grid'}++;

		if (scalar @certs != scalar @servercerts) {
			say Dumper(\@certs);
			say Dumper(\@servercerts);
			croak("Certs != servercerts");
		}

		return if ( defined($self->seencache->{$full_hash_chain_sorted}) );

		my $test = CertReader::DB::Chain->new(db => $self->db, chain_hash => $full_hash_chain_sorted);

		if (  $test->load(use_key => 'chain_hash', speculative => 1) ) {
			$self->seencache->{$full_hash_chain_sorted} = 1;
			return;
		}

		my $chain = CertReader::DB::Chain->new(
			chain_hash => $full_hash_chain_sorted,
			certificates => \@certs,
		);

		eval {
			$chain->save;
		};
	}
}

sub run {
	my $self = shift;
	my $postfix = $self->tablepostfix;

	my $parse = Bro::Log::Parse->new({empty_as_undef => 1, diamond=>1});
	my $headers = $parse->headers();
	my $firstts;

	# we create per-file statistics and only want one file active at any moment.
	if ( scalar @{$self->argv_copy} != 1 ) {
		croak("expecting one file argument");
	}

	my $file = $self->argv_copy->[0];
	$file =~ s/\.xz$//;
	my $outfile = $file.$self->fileextension;
	$interestingsignaturesfn = $outfile.".interesting";
	if ( -f $outfile ) {
		say "Skipping duplicate file $file";
		exit(0);
	}
	$file =~ s#^.*/dropboxes/##;

	$stats{'file_name'} = $file;

	unless ( $self->nodb ) {
		$self->db;
		my $test = CertReader::DB::SeenStats->new(file_name => $file);
		if ( $test->load(use_key => 'file_name', speculative=> 1) ) {
			# damn we know that one
			say "skipping duplicate $file";
			exit(0);
		}
	}

	say "Working on $file";

	if ( defined($self->interestingsignaturesfile) ) {
		open(my $ifh, "<", $self->interestingsignaturesfile);
		while ( my $line = <$ifh> ) {
			chomp($line);
			$interestingsignatures{$line}++;
		}
	}

	if($parse->{json_file}) {
		$stats{fields} = Pg::hstore::encode({json => 1});
	} else {
		if ( defined($headers->{fields}) && defined($headers->{types})) {
			my @fields = split(/\t/, $headers->{fields});
			my @types = split(/\t/, $headers->{types});
			if (scalar @fields == scalar @types ) {
				$stats{fields} = Pg::hstore::encode({zip(@fields, @types)});
			}
		}
	}

	SEENLINE: while ( my $out = getLine($parse) ) {
		my %f = %$out;

		my @expandarrays = qw/server_certs client_ciphers client_curves point_formats ssl_client_exts/;

		for my $name ( @expandarrays ) {
			if ( defined($f{$name}) && ref($f{$name}) eq "ARRAY" ) {
				$f{$name} = split/,/, $f{$name};
			}
		}

		if ( defined $f{version_num} && ! (defined$f{version}) ) {
			my $vnum = $f{version_num};
			my $cnum = $f{cipher_num};
			if ( int($vnum/0xFF) == 0x7F ) { # 1.3 draft
				$f{version} = "TLSv13-draft".$vnum%0x7F;
			} else {
				$f{version} = defined($tls_versions{$vnum}) ? $tls_versions{$vnum} : "unknown-$vnum";
			}
			$f{cipher} = defined($tls_ciphers{$cnum}) ? $tls_ciphers{$cnum} : "unknown-$cnum";
		}

		$self->countline(\%f, $parse->line());

		$f{"ts"} =~ s/\..*$//;
		$firstts //= $f{"ts"};
		if ( $f{"ts"} > (time() + 10000000) ) {
			# heh. sure. it's christmas.
			# use current time as approximation
			# for readseen timestamps are actually kind of important. and because we just are not sure...
			# ignore file
			say STDERR "Invalid timestamps in file $ARGV";
			exit(0);
		}

		$self->seenstats(\%f) unless ( $self->disableseenfull );
	}

	if ( !defined($stats{begin_time}) && defined($stats{all_ports}) ) {
		# you got to be kidding me? no correct timestamps?
		croak("File has all incorrect timestamps. We give up.");
	}

	my %dumpstats = %stats;


 	for my $var (@stat_list)	{
	 	no strict 'refs';
		$stats{$var} = Pg::hstore::encode(\%$var);
	 }

	for my $var (@stat_list)	{
		no strict 'refs';
		$dumpstats{$var} = \%$var;
	}

	# delete all but the top-100 from sniips.
	for my $fingerprint (keys %tls_signature_sniips) {
		if ( defined($tls_signature_sniips{$fingerprint}{snis}) ) {
			my $snis = $tls_signature_sniips{$fingerprint}{snis};
			my $count = 0;
			for my $sni (sort { $snis->{$b} <=> $snis->{$a} } keys %$snis) {
				$count++;
				delete $$snis{$sni} if ($count > 100);
			}
		}
		my $ips = $tls_signature_sniips{$fingerprint}{ips};
		my $count = 0;
		for my $ip (sort { $ips->{$b} <=> $ips->{$a} } keys %$ips) {
			$count++;
			delete $$ips{$ip} if ($count > 100);
		}
		my $numconns = $tls_signature_sniips{$fingerprint}{connections};
		$tls_signature_sniips{$fingerprint}{total_duration} = $tls_signature_sniips{$fingerprint}{duration}->bdstr();
		$tls_signature_sniips{$fingerprint}{duration}->bdiv($numconns);
		$tls_signature_sniips{$fingerprint}{client_bytes}->bdiv($numconns);
		$tls_signature_sniips{$fingerprint}{server_bytes}->bdiv($numconns);
		$tls_signature_sniips{$fingerprint}{duration} = $tls_signature_sniips{$fingerprint}{duration}->bdstr();
		$tls_signature_sniips{$fingerprint}{client_bytes} = $tls_signature_sniips{$fingerprint}{client_bytes}->bdstr();
		$tls_signature_sniips{$fingerprint}{server_bytes} = $tls_signature_sniips{$fingerprint}{server_bytes}->bdstr();
	}

	$dumpstats{signature_sniips} = \%tls_signature_sniips;

	DumpFile($outfile, \%dumpstats);
	unless ( $self->nodb ) {
		my $dbstats = CertReader::DB::SeenStats->new(%stats);
		$dbstats->save;
	}

	exit(0);
}


1;

