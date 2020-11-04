package CertReader::App::NumberOfLogsperConns;

# Give the number of logs that we see for how many connections

use 5.16.1;
use strict;
use warnings;
use Carp;
use autodie;
use Pg::hstore;
use Data::Dumper;
use List::Util qw/uniq/;

use Moose;
with 'MooseX::Runnable';
with 'MooseX::Getopt';
with 'CertReader::Base';
with 'CertReader::ORM';

use Crypt::OpenSSL::X509;

my %numbers;
my %numberlogs;

sub run {
	my $self = shift;

	my %logmap;
	my %logmapdesc;
	say STDERR "Loading sct_hashes.tsv";
	my $hashes_file = $ENV{"HOME"} . "/syd-ct/data-exploration/sct_hashes.tsv";
	open(my $hfh, "<", $hashes_file);
	<$hfh>; # swallow header;
	while ( my $line = <$hfh> ) {
		chomp($line);
		my ($sha256, $sha1, $description, $operator) = split(/\t/, $line);
		$logmap{$sha1} = $operator;
		$logmapdesc{$sha1} = $description;
	}
	close($hfh);

	my $iter = CertReader::DB::SeenStats::Manager->get_seenstats_iterator_from_sql(
		db => $self->db,
		inject_results => 1,
		sql => "SELECT * FROM seen_stats_".$self->tablepostfix.";",
	);

	my $all = 0;
	while ( my $line = $iter->next ) {
		my $r = Pg::hstore::decode($line->ct_logidcombinations_cert);
		while ( my ($ids, $count) = each %$r ) {
			my @logs = split(/,/, $ids);
			my @operators = uniq map {$a=$_;if(defined($logmap{$a})){$a=$logmap{$a}}$a} split(/,/, $ids);
			$numbers{scalar @operators}+=$count;
			$numberlogs{scalar @logs}+=$count;
			$all += $count;
			#if ( scalar @operators == 4) {
			#	say $ids, join(",", @operators);
			#}
		}

	}

	while ( my ($ops, $count) = each %numbers ) {
		say "\\expandafter\\def\\csname UCoperatornumbers-$ops-\\endcsname{$count}";
		say "\\expandafter\\def\\csname UCoperatornumbersp-$ops-\\endcsname{".sprintf("%.2f", 100*$count/$all)."}";
	}
	while ( my ($ops, $count) = each %numberlogs ) {
		say "\\expandafter\\def\\csname UClognumbers-$ops-\\endcsname{$count}";
		say "\\expandafter\\def\\csname UClognumbersp-$ops-\\endcsname{".sprintf("%.2f", 100*$count/$all)."}";
	}
}

1;
