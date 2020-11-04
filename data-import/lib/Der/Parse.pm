package Der::Parse;

use 5.14.1;
use strict;
use warnings;

use autodie;
use Carp;
use Scalar::Util qw/openhandle/;

use Data::Dumper;  # debugging

use Moose;

my $json = eval {
    require JSON;
    JSON->import();
    1;
}; # true if we support reading from json

# Adapted from Bro::Log::Parse
sub new {
    my $class = shift;
    my $arg = shift;

    my $self = {};
    $self->{line} = undef;

    if ( !defined($arg) ) {
        $self->{diamond} = 1;
    } elsif ( ref($arg) eq 'HASH' ) {
        $self = $arg;
    } elsif ( defined(openhandle($arg)) ) {
        $self->{fh} = $arg;
    } else {
        $self->{file} = $arg;
    }

    bless $self, $class;

    if ( defined($self->{file}) && !(defined($self->{fh})) ) {
        unless ( -f $self->{file} ) {
            croak("Could not open ".$self->{file});
        }

        open( my $fh, "<", $self->{file} )
            or croak("Cannot open ".$self->{file});
        $self->{fh} = $fh;
    }

    if ( !defined($self->{fh}) && ( !defined($self->{diamond}) || !$self->{diamond} ) ) {
        croak("No filename given in constructor. Aborting");
    }

    return $self;
}

sub getLine {
    my $self = shift;

    my $in = $self->{fh};
    my $file_content = do { local $/; defined($in) ? <$in> : <>};

    return $file_content;
}

1;
