package CertReader::App::Readcertmap;

# read a certmap file into the database

use 5.14.1;
use strict;
use warnings;

use Carp;
use Crypt::OpenSSL::X509;
use Data::Dumper;
use Digest::MD5 qw/md5_hex/;
use Digest::SHA qw/sha1_hex/;
use Date::Parse;

use Bro::Log::Parse 0.07;
use Zgrab::Log::Parse;
use Zgrab::Log::ParseLine;
use Der::Parse;
use MIME::Base64;
use DateTime::Format::ISO8601;

use Moose;

with 'CertReader::Base';
with 'CertReader::ReadCerts';

has 'source' => (
	is => 'rw',
	isa => 'Int',
	required => '1',
	documentation => "Number of the source. Current mapping: AIA:0, Rest: Private, sorry.",
);

has 'zgrab_format' => (
	is => 'ro',
	isa => 'Bool',
	required => '0',
	default => '0',
	documentation => "Use if the input is in zgrab format (e.g. censys data).",
);

has 'der_format' => (
	is => 'ro',
	isa => 'Bool',
	required => '0',
	default => '0',
	documentation => "Use if the input file contains a single(!!!) der-formatted certificate.",
);

has 'cacerts' => (
	is => 'ro',
	isa => 'Bool',
	required => '0',
	default => '0',
	documentation => "Only store CA certificates in the database.",
);

has 'debug' => (
	is => 'ro',
	isa => 'Bool',
	required => '0',
	default => '0',
	documentation => "Enable some debug output.",
);

has 'startline' => (
	is => 'ro',
	isa => 'Int',
	required => '0',
	default => '0',
	documentation => "Intended for debugging. Skip first n lines of input",
);

has 'disable_sanitycheck_format' => (
    is => 'rw',
    isa => 'Bool',
    required => '0',
    default => 0,
    documentation => "Disable check if the input format deviates from expectations (currently only available for json)",
);

# sha1 hashes of unparseable certs that we skip. It is a tad sad, that we have to do this, but for the moment I do not really know a better way - I just do not want to ignore errors and this seems
# to happen very rarely.
my %badcerts = (
);

sub getLine {
	my ($self, $parse) = @_;
	my $out;
	eval {
		$out = $parse->getLine();
		} or do {
		return undef if ( ! $@ );
		say "Error while trying: $@";
		say "Trying to redo";
		# ok, we jump _1_ line of errors...
		$out = $parse->getLine();
		};
	return $out;
}

sub preprocess_zgrab_cert {
	my ($r_zgrabcert, $timestamp) = @_;

	my %cert;
	$cert{cert} = $r_zgrabcert->{raw}; # base64 encoded DER/ASN1 encoded certificate
	$cert{fingerprint_sha1} = $r_zgrabcert->{parsed}{fingerprint_sha1};
	$cert{cert_hash} = $r_zgrabcert->{parsed}{fingerprint_md5};
	$cert{ts} = $timestamp;

	return \%cert;
}

sub preprocess_zgrab_format {
	my $self = shift;
	my $r_zgrabjson = shift;
	my $linedata = Zgrab::Log::ParseLine->new( data => $r_zgrabjson, sanitycheck_format => !$self->disable_sanitycheck_format );

	my @certs; # a list of certificates
	my $timestamp;

	my $datetime = DateTime::Format::ISO8601->parse_datetime($linedata->get_timestamp());
	$timestamp = $datetime->epoch();

	my $r_certdata;
	my $r_certs = $linedata->get_servercerts();
	foreach $r_certdata (@$r_certs) {
		$r_certdata = preprocess_zgrab_cert($r_certdata, $timestamp);
		push(@certs, $r_certdata);
	}

	my $r_chaindata = $linedata->get_certchains();
	for my $chain (@$r_chaindata){
		foreach $r_certdata (@$chain) {
			$r_certdata = preprocess_zgrab_cert($r_certdata, $timestamp);
			push(@certs, $r_certdata);
		}
	}

	my $error = $linedata->get_error();
	my $errorcomponent = $linedata->get_errorcomponent();
	if (defined($errorcomponent)) {
		if ($errorcomponent =~ /tls/) {
			if ($error =~ /tls: failed to parse certificate from server:(.*?)/) {
				croak("No certificates: $error");
			}
		}
	}

	if (@certs < 1) {
		if ($error =~ /i\/o timeout/ && $errorcomponent =~ /tls/) {
			croak("No certificates: i/o timeout during TLS handshake");
		} elsif ($error =~ /tls: server advertised unrequested ALPN extension/ && $errorcomponent =~ /tls/) {
			croak("No certificates: server advertised unrequested ALPN extension");
		} elsif ($error =~ /local error: internal error/ && $errorcomponent =~ /tls/) {
			croak("No certificates: local error: internal error");
		} elsif ($error =~ /read tcp .*: read: connection reset by peer/ && $errorcomponent =~ /tls/) {
			croak("No certificates: connection reset by peer");
		} elsif ($error =~ /tls: received unexpected handshake message of type \*tls.certificateMsg when waiting for \*tls.certificateMsg/ && $errorcomponent =~ /tls/) {
			croak("No certificates: unexpected handshake message (tls.certificateMsg vs tls.certificateMsg)");
		} elsif ($error =~ /tls: received unexpected handshake message of type \*tls.serverHelloDoneMsg when waiting for \*tls.certificateMsg/ && $errorcomponent =~ /tls/) {
			croak("No certificates: unexpected handshake message (tls.serverHelloDoneMsg vs tls.certificateMsg)");
		} elsif ($error =~ /EOF/ && $errorcomponent =~ /tls/) {
			croak("No certificates: EOF");
		} elsif ($error =~ /tls: server selected unsupported compression format/ && $errorcomponent =~ /tls/) {
			croak("No certificates: server selected unsupported compression format");
		}
		croak("Unexpected zgrab error case: $error (at component $errorcomponent)");
	}

	return \@certs;
}

sub preprocess_der_format {
	my $self = shift;
	my $cert_binary = shift;

	my %cert;
	$cert{cert} = encode_base64($cert_binary);
	$cert{fingerprint_sha1} = sha1_hex($cert_binary);
	$cert{cert_hash} = md5_hex($cert_binary);
	$cert{ts} = time;

	return \%cert;
}

sub run {
	my $self = shift;

	croak("Need source") unless (defined($self->source));

	croak("Need file") unless (scalar @ARGV >= 1);

	my $certerrors_log = "certerrors.txt";
	my $certerrors_cnt = 0;
	open(my $certerrors, ">>", $certerrors_log);

	my $parse;
	if ($self->zgrab_format) {
		$parse = Zgrab::Log::Parse->new();
	} elsif ($self->der_format) {
		$parse = Der::Parse->new();
	} else {
		$parse = Bro::Log::Parse->new();
	}
	my $lastts;
	my $redocount = 0;
	my $linecount = 0;
	my $last_argv = "";

	LINE: while ( my $out = $self->getLine($parse) ) {

		next if $. < $self->startline; # Fast skip of lines for debugging

		if (!($ARGV eq $last_argv)) {
			if (!$last_argv eq "") {
				say "\t finished processing of $last_argv: processed $linecount lines (total lines: $.).";
			}
			$linecount = 0;
			$last_argv = $ARGV;
			say localtime() . "\tINFO: Starting processing of $ARGV";
		}
		$linecount += 1;
		say localtime() . "\tINFO: \tReached line $linecount on $ARGV (total processed lines: $.)" if ($linecount % 10000 == 0);

		my @certs;
		eval {
			if ($self->zgrab_format) {
				$out = preprocess_zgrab_format($self, $out);
				@certs = @$out;
			} elsif ($self->der_format) {
				$out = preprocess_der_format($self, $out);
				push(@certs, $out);
			} else {
				# Bro data contains only one certificate per line
				push(@certs, $out)
			}
			1;
		} or do {
			if ($self->zgrab_format) {
				my $warn_message = 0;
				my $store_error = 0;
				if ($@ =~ /No certificates: /) {
					$warn_message = "Skipping line with tls_data but without certs";
				} elsif ($@ =~ /no tls data (.*?)/) {
					# warn_message = "Skipping line without tls data";
				} else {
					$warn_message = "unknown error";
					$store_error = 1;
				}

				warn "$warn_message -- $@ \t($ARGV line $.)" if $warn_message;
				if ($store_error) {
					say $certerrors "$@ ($ARGV line $.)"; # Store error for later analysis
					$certerrors->flush();
					$certerrors_cnt += 1;
				}
				next LINE;
			}
		};

		# If the certs array is still empty, we encountered an yet unknown special case. Make us recognize this.
		croak("No certificates ($ARGV line $.)") if @certs < 1;

		CERT: foreach my $certs_entry (@certs) {
			my %f = %$certs_entry;
			croak("No cert ($ARGV line $.)") unless defined($f{cert});
			my $binary = ($self->zgrab_format or $self->der_format)? decode_base64($f{cert}) : pack("H*", $f{"cert"});
			if ( $redocount > 2 ) {
				croak("Not implemented for zgrab data") if $self->zgrab_format;
				# and we cannot even trust the binary that comes from Bro. In rare, random cases, the certificate is actually...
				# ... well, not the certificate. Instead there is random crap appended to the ASN.1 (might be worth a look sometime just
				# to figure out what the heck is going on there). In any case - in these cases, our nice calculates certificate hashes and
				# fingerprints are completely off. Which is not helpful. So - we actually already have to invoke all the OpenSSL magic, just
				# to determine the correct hash of the certificate. Let's do that...
				my $c = Crypt::OpenSSL::X509->new_from_string($binary, Crypt::OpenSSL::X509::FORMAT_ASN1);
				$binary = $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
			}
			my $ts = $f{ts};

			$f{cert_hash} = md5_hex($binary); # apparently we cannot trust Bro-generated md5-sums.
			$f{fingerprint_sha1} = sha1_hex($binary);

			croak("No ts?") unless(defined($ts));

			if ( !$self->zgrab_format and ( $ts > 1577836800 || $ts < 1293840000 ) ) {
				if ( defined($lastts) ) {
					$ts = $lastts; #yep. dirty. blame it on logfile errors.
				} else {
					# ok, we do not even have an earlier timestamp that is correct.
					# Yes, this happens :(
					# Let's try to use the file open date instead.
					my %headerh = map {m/#(\w+)\s+(.*)/; $1 => $2 } @{$parse->headerlines()};
					if ( defined($headerh{open}) ) {
						$ts = str2time($headerh{open});
					} else {
						# great. This file is old enough that we don't have an open header.
						# Let's try the filename (yes, grasping for straps here)
						my $fn = $ARGV;
						if ( $fn =~ m#ssl_certmap.(\d\d\d\d)-(\d\d)-(\d\d)-(\d\d)-(\d\d)-(\d\d).log.xz# ) {
							$ts = str2time("$1-$2-$3 $4:$5:$6");
						} else {
							croak("First timestamp in file $ARGV is $ts, which is wrong; no open date. Cannot parse filename");
						}
					}
					croak("Give up with all incorrect timestamps") if ( $ts > 1577836800 || $ts < 1293840000 );
				}
				say "Using replacement timestamp $ts due to incorrect file timestamp ".$f{ts};
			}

			my $res = 0;

			eval {
				$res = $self->testIfCertExists(1, $f{fingerprint_sha1}, $self->source, DateTime->from_epoch( epoch => $ts) );
				1;
			} or do {
				say "Redoing here - after testIfCertExists: $@";
				say $parse->line();
				$redocount++;
				die("More than 10 redos. Aborting") if $redocount > 10;
				redo CERT;
			};
			$lastts = $ts;
			if ( $res ) {
				# we already had this one
				warn "Skipping $f{fingerprint_sha1}: already in database ($ARGV)" if $self->debug;
				next CERT;
			}


			my $c;
			eval {
				$c = Crypt::OpenSSL::X509->new_from_string($binary, Crypt::OpenSSL::X509::FORMAT_ASN1);
			} or do {
				# encountered unreadable certificate. Skip it.
				warn "Unreadable cert $f{fingerprint_sha1} ($ARGV)" if $self->debug;
				next CERT;
			};

			my $cert = $self->buildDbCert($c, $self->source, DateTime->from_epoch( epoch => $ts ) );
			next unless ( $cert ) ;

			eval {
				$cert->save;
				warn "Stored $f{fingerprint_sha1} in db ($ARGV)" if $self->debug;
				1;
			} or do {
				if ( defined($badcerts{$cert->fingerprint_sha1}) ) {
					warn "Skipping known bad certificate... ".$cert->fingerprint_sha1.": ".$badcerts{$cert->fingerprint_sha1};
					next CERT;
				}
				# hopefully duplicate insert. retry.
				say "Redoing duplicate insert for $ARGV.  ".$cert->cert_hash." ".$cert->fingerprint_sha1;
				$redocount++;
				if ( $redocount > 10 ) {
					burp('badcert.cert', $cert->der);
					warn "More than 10 redos for $ARGV and ".$cert->cert_hash.", ".$cert->fingerprint_sha1.". Aborting and dumping to badcert.cer.";
					#die("More than 10 redos for $ARGV and ".$cert->cert_hash.", ".$cert->fingerprint_sha1.". Aborting and dumping to badcert.cer.");
					say $certerrors $cert->cert_hash."\t".$cert->fingerprint_sha1."\t".$ARGV."\t".$f{cert};
					$certerrors_cnt += 1;
					next CERT;
				}
				redo CERT;
			};

			eval {
				$self->storeExtensions($c, $cert);
			}; # if this fails it already has been saved by someone else.

			$res = $self->testIfCertExists(0, $cert->fingerprint_sha1);

			if ( !$res ) {
				croak("Certificate ".$cert->fingerprint_sha1."inserted but not present!");
			}

			$redocount = 0;
		}
	}

	say "--- Finished ---";
	say "\n### WARNING ####" if $certerrors_cnt;
	say "Encountered $certerrors_cnt errors (see $certerrors_log)";

	exit(1) if $certerrors_cnt;
	exit(0);
}

1;
