package CertReader::ReadCerts;

# package with utility functions that do the actual certificate reading and parsing

use 5.14.1;

use Encode;

use strict;
use warnings;

use Moose::Role;
use Carp;
use Digest::MD5 qw/md5_hex/;
use Digest::SHA qw/sha1_hex sha256_hex sha512_hex/;
use Time::Piece;

# Functions tests if a certificate already exists in the db. If it does,
# it adds the provided or current source as a source to the certificate
sub testIfCertExists {
	my ( $self, $update, $hash, $source, $time ) = @_;

	croak("Missing required parameter in testIfCertExists") unless ( defined($update) && defined($hash) );

	if ( $update ) {
		croak("Missing required parameter in testIfCertExists") unless( defined($source) && defined($time) );
	}

	if ( $self->usememcached ) {
		my $memd = $self->memd;
		my $memget = $memd->get("c$hash$source");
		if ( defined($memget) ) {
			# already in DB, return cached ID.
			return $memget;
		}
	}

	my $key = (length($hash) > 34) ? 'fingerprint_sha1' : 'cert_hash';

	my $test = CertReader::DB::Certificate->new(db => $self->db, $key => $hash);

	if ( $test->load(use_key => $key, speculative => 1) ) {
		my $save = 0;

		$self->memd->set("c$hash$source", $test->id) if ( $self->usememcached );

		if ( $update == 0 ) {
			return $test->id;
		}

		unless ( $test->source->bit_test($source) ) {
			$test->source->Bit_On($source);
			$save = 1;
		}

		if ( $test->first_seen > $time ) {
			$test->first_seen($time);
			$save = 1;
		}

		$test->save if ( $save );

		return $test->id;
	}

	return 0;
}

sub buildDbCert {
	my ( $self, $c, $thesource, $seen) = @_;

	croak("Missing required parameter in buildDbCert") unless ( defined($c) && defined($thesource) && defined($seen) );

	$thesource //= $self->source;

	my $selfsigned = $c->is_selfsigned ? 1 : 0;

	my $ca;
	my $altname;
	my $crl;
	my $akid;
	my $skid;
	my $key_usage;
	my $extkey_usage;
	my $extensions = {};
	my $pathlen;
	if ( $c->num_extensions > 0 ) {
		$extensions = $c->extensions_by_name;
	}
	while ( my ($name, $ext) = each %$extensions ) {
		if ( $name eq "authorityKeyIdentifier" ) {
			$akid = $ext->to_string;
			chomp($akid);
			#$akid =~ s/^keyid://;
		} elsif ( $name eq "subjectKeyIdentifier" ) {
			$skid = $ext->to_string;
			chomp($skid);
		} elsif ( $name eq "crlDistributionPoints" ) {
			$crl = $ext->to_string;
			chomp($crl);
			#croak ( "unknown crl scheme: $crl" ) unless
				$crl =~ s/.*(http\:\/\/.*)$/$1/s;
		} elsif ( $name eq "subjectAltName" ) {
			$altname = $ext->to_string;
			chomp($altname);
			# filter out invalid utf-8
			$altname = encode( "UTF-8", $altname );
		} elsif ( $name eq "basicConstraints" ) {
			my $b = $ext->to_string;
			chomp($b);
			if ( $b =~ m#pathlen:(\d+)# ) {
				$pathlen = $1;
			}

			if ( $b =~ m#CA:FALSE# ) { # jap, we have some where this happens. rly.
				$ca = 0;
			} elsif ( $b =~ m#CA:TRUE#) {
				$ca = 1;
			} elsif ( $b =~ m#^\s*$#) {
			} else {
				croak ("unknown basicConstraint: $b");
			}
		} elsif ( $name eq "keyUsage" ) {
			$key_usage = $ext->to_string;
			chomp($key_usage);
		} elsif ( $name eq "extendedKeyUsage" ) {
			$extkey_usage = $ext->to_string;
			chomp($extkey_usage);
		}
	}

	if ($self->cacerts) {
		warn "Skipping non-CA certificate ($ARGV)" if $self->debug;
		return undef if !defined($ca) or $ca == 0;
	}

	my $version = $c->version ? $c->version : 0;
	$version++;

	my $expo;
	my $key_curve;
	my $modulus;
	my $bit_length;
	eval {
		if ( $c->key_alg_name =~ m#^rsa#  ) {
			$expo = hex($c->exponent) if ( length($c->exponent) < 100 );
		} elsif ( $c->key_alg_name =~ m#^dsa# ) {
		} else {
			$key_curve = $c->curve;
		}

		$bit_length = $c->bit_length;
		$modulus = $c->modulus;
		1;
	} or do {
		#open (my $err, ">>", "certerror.log");
		say STDERR "Could not parse key of certificate: $@ - hash: ".$c->fingerprint_md5." - Subject: ".$c->subject."  - Alg: ".$c->key_alg_name;
		say STDERR "Inserting without private key information!";
		#say $err "Could not parse key of certificate $hash";
		#burp("out.der",  $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1));
		#close $err;
		#return 0;
	};

	my $source = Bit::Vector->new(20);
	$source->Bit_On($thesource);
	my $subject = $c->subject;
	$subject = encode( "UTF-8", $subject);
	my ($spki_sha1, $spki_sha256, $spki_sha512);
	eval {
		$spki_sha1 = lc(sha1_hex($c->spki));
		$spki_sha256 = lc(sha256_hex($c->spki));
		$spki_sha512 = lc(sha512_hex($c->spki));
	};

	my $not_after;
	$not_after = eval { Time::Piece->strptime($c->notAfter, "%b %d %T %Y %Z")." GMT" } or do {
			burp('badcert.cert', $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1));
			say STDERR "Date not valid: ".$c->notAfter." hash: ".$c->fingerprint_md5." - Subject: ".$c->subject." dumped";
			# let's just try of postgres will accept it.
			$not_after = $c->notAfter;
		};
	my $not_before;
	$not_before = eval { Time::Piece->strptime($c->notBefore, "%b %d %T %Y %Z")." GMT" } or do {
			burp('badcert.cert', $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1));
			say STDERR "Date not valid: ".$c->notAfter." hash: ".$c->fingerprint_md5." - Subject: ".$c->subject." dumped";
			$not_before = $c->notBefore;
		};

	my $cert = CertReader::DB::Certificate->new(
		der => $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1),
		version => $version,
		serial => $c->serial,
		sig_algo => $c->sig_alg_name,
		issuer => $c->issuer,
		key_curve => $key_curve,
		not_before => $not_before,
		not_after => $not_after,
		subject => $subject,
		key_algo => $c->key_alg_name,
		key_mod => $modulus,
		key_expo => $expo,
		key_length => $bit_length,
		ca => $ca,
		path_len => $pathlen,
		#ext_usage => $extkey_usage,
		#key_usage => $key_usage,
		#crl => $crl,
		subj_alt_name => $altname,
		cert_hash => md5_hex( $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1) ),
		fingerprint_sha1 => sha1_hex( $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1) ),
		fingerprint_sha256 => sha256_hex( $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1) ),
		fingerprint_sha512 => sha512_hex( $c->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1) ),
		spki_sha1 => $spki_sha1,
		spki_sha256 => $spki_sha256,
		spki_sha512 => $spki_sha512,
		selfsigned => $selfsigned,
		#akid => $akid,
		#skid => $skid,
		source => $source,
		first_seen => $seen,
		db => $self->db
	);

	return $cert;
}

sub readsinglecert {
	my ($self, $cert, $mode, $source) = @_;
	$source //= 0;
	# Source mapping:
	#   cross-sign root-stores: default (0)   TODO should get a meaningful value (15?)
	#   cross-sign intermediates: default (0)   TODO TODO should get a meaningful value (15?)
	#   crt.sh: 14

	my $c = Crypt::OpenSSL::X509->new_from_string($cert, $mode);

	# most important thing first - create hash in the same way we do our hashes.
	my $fingerprint_sha1 = lc($c->fingerprint_sha1);
	$fingerprint_sha1 =~ s/://g;

	my $id = $self->testIfCertExists(1, $fingerprint_sha1, $source, DateTime->now()); # AIA gets source 0

	return $id if $id; # certificate already in db

	my $dbcert = $self->buildDbCert($c, $source, DateTime->now()); # aia gets source 0 again

	$dbcert->save;

	$self->storeExtensions($c, $dbcert);

	$self->memd->set("c$fingerprint_sha1"."$source" , $dbcert->id) if ( $self->usememcached );

	return $dbcert->id;
}

# Takes a certificate and stores all extensions in the db.
# Pretty easy
sub storeExtensions {
	my ( $self, $c, $cert ) = @_;

	my $extensions = {};
	if ( $c->num_extensions > 0 ) {
		$extensions = $c->extensions_by_name;
	}

	while ( my ($name, $ext) = each %$extensions ) {
		my $critical = $ext->critical ? 1 : 0;
		my $extn = CertReader::DB::CertificateExtension->new(
			certificate => $cert,
			critical => $critical,
			name => $name,
			value => $ext->to_string,
			oid => $ext->object->oid,
			db => $self->db
		);

		eval {
			$extn->save;
		} or do {
			say @_;
		}
	}
}

sub burp {
  my( $file_name ) = shift ;
  open( my $fh, ">$file_name" ) || carp "can't create $file_name $!" ;
  print $fh @_ ;
}


1;
