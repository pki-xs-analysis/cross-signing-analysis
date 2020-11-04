package CertReader::Base;

# this role loads all the stuff that classes that actually interact with the database
# and the certificates and do verification require.

use 5.14.1;

use Carp;
use Cache::Memcached;

use Moose::Role;
with 'MooseX::Getopt';
with 'MooseX::Runnable';

with 'CertReader::ORM';

has '_mtime' => (
	is => 'rw',
	required => 0,
	accessor => 'mtime',
	documentation => 'modification time of the current file. Used instead of the in-file timestamps, if they are bogus',
);

has '_argv_copy' => (
	is => 'rw',
	required => 0,
	accessor => 'argv_copy',
	isa => 'ArrayRef',
);

has '_memd' => (
	is => 'rw',
	accessor => 'memd',
	default => sub { new Cache::Memcached { 'servers' => ['$ENV{HOME}/mem'] }; },
);

has 'usememcached' => (
        is => 'rw',
        isa => 'Bool',
        documentation => "Use memcached to speed up some operations (cert reading)",
        default => 0,
);

=head2 before-run

Run initialization before the actual run-method of the app is executed.

Mainly sets up a sane @ARGV

=cut

before 'run' => sub {
	my $self = shift;

	@ARGV = @{$self->extra_argv}; # we only want unparsed arguments in argv...
	$self->argv_copy([ @ARGV ]);

	if ( defined($ARGV[0]) && -f $ARGV[0] ) {
		$self->mtime(( stat $ARGV[0] )[9]);
	}

	# black magic stolen from the internet... make all .xz arguments go through xzcat.
	s{
	    ^            # make sure to get whole filename
	    (
	      [^'] +     # at least one non-quote
	      \.         # extension dot
	      (?:        # now either suffix
		  xz
	       )
	    )
	    \z           # through the end
	}{xzcat '$1' |}xs for @ARGV;
	s{
	    ^            # make sure to get whole filename
	    (
	      [^'] +     # at least one non-quote
	      \.         # extension dot
	      (?:        # now either suffix
		 gz
	       )
	    )
	    \z           # through the end
	}{gzip -cd '$1' |}xs for @ARGV;
	s{
	    ^            # make sure to get whole filename
	    (
	      [^'] +     # at least one non-quote
	      \.         # extension dot
	      (?:        # now either suffix
		 lz4
	       )
	    )
	    \z           # through the end
	}{lz4 -cd '$1' |}xs for @ARGV;
	s{
	    ^            # make sure to get whole filename
	    (
	      [^'] +     # at least one non-quote
	      \.         # extension dot
	      (?:        # now either suffix
		 br
	       )
	    )
	    \z           # through the end
	}{brotli -cd '$1' |}xs for @ARGV;
	s{
	    ^            # make sure to get whole filename
	    (
	      [^'] +     # at least one non-quote
	      \.         # extension dot
	      (?:        # now either suffix
		 der
	       )
	    )
	    \z           # through the end
	}{cat '$1' |}xs for @ARGV;
};


sub burp {
	shift if ( defined $_[0] && ref($_[0]) && UNIVERSAL::can($_[0], 'isa') );

	my( $file_name ) = shift ;
	open( my $fh, ">$file_name" ) ||
									 croak "can't create $file_name $!" ;
	print $fh @_ ;
}


sub generate_store_no {
	shift if ( defined $_[0] && ref($_[0]) && UNIVERSAL::can($_[0], 'isa') );

	my $num = shift;
	my $pow = 1<<$num;

	my $store = unpack("B16", pack("n", $pow));

	$store =~ s/^\d{6}//;
	return $store;
}


1;
