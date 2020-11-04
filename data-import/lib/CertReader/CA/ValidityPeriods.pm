package CertReader::CA::ValidityPeriods;

use 5.16.1;

use strict;
use warnings;
use Carp;

use Moose;

use Date::Parse;
use List::Util qw[min max];

has 'validity_periods' => (
    is => 'rw',
    isa => 'ArrayRef',
    required => 1,
    default => sub{ [] },
);

sub get_periods {
    return shift->validity_periods;
}

sub add_period {
    my ($self, $not_before, $not_after) = @_;

    my $new_period = CertReader::CA::ValidityPeriods::ValidityPeriod->new(
        not_before => $not_before,
        not_after => $not_after,
    );

    my $updated_periods = [];

    for my $old_period (@{$self->validity_periods}) {
        my $overlapping = 0;

        if ($new_period->get_notbefore_ts < $old_period->get_notbefore_ts) {
            if ($new_period->get_notafter_ts < $old_period->get_notbefore_ts) {
                ;  # no overlap
            } else {
                $overlapping = 1;
                if ($new_period->get_notafter_ts > $old_period->get_notafter_ts) {
                    ;
                } else {
                    $new_period->set_notafter($old_period->get_notafter);
                }
            }
        } else {
            if ($old_period->get_notafter_ts < $new_period->get_notbefore_ts) {
                ;  # no overlap
            } else {
                $overlapping = 1;
                $new_period->set_notbefore($old_period->get_notbefore);
                if ($new_period->get_notafter_ts > $old_period->get_notafter_ts) {
                    ;
                } else {
                    $new_period->set_notafter($old_period->get_notafter);
                }
            }
        }

        if (! $overlapping) {
            push(@{$updated_periods}, $old_period);
        }
    }
    push(@{$updated_periods}, $new_period);

    $self->validity_periods($updated_periods);
}

sub add_periods {
    # $periods must be a CertReader::CA::ValidityPeriods
    my ($self, $periods) = @_;

    for my $period (@{$periods->get_periods}) {
        $self->add_period($period->get_notbefore, $period->get_notafter);
    }
}

sub restrict_to_periods {
    # Limits the periods of this object to the overlap with the periods of $limiting_periods
    # @params:
    #   $limiting_periods must be a CertReader::CA::ValidityPeriods
    my ($self, $limiting_periods) = @_;

    my $restricted_periods = CertReader::CA::ValidityPeriods->new();

    for my $this_period (@{$self->get_periods}) {
        for my $limiting_period (@{$limiting_periods->get_periods}) {
            my $not_before = $this_period->get_notbefore;
            if ($this_period->get_notbefore_ts < $limiting_period->get_notbefore_ts) {
                $not_before = $limiting_period->get_notbefore;
            }

            my $not_after = $this_period->get_notafter;
            if ($this_period->get_notafter_ts > $limiting_period->get_notafter_ts) {
                $not_after = $limiting_period->get_notafter;
            }

            if (str2time($not_before, "GMT") <= str2time($not_after, "GMT")) {
                $restricted_periods->add_period($not_before, $not_after);
            }
        }
    }
    # say "(" . $self->to_string . ") and (" . $limiting_periods->to_string . ") = (" . $restricted_periods->to_string . ")";  # debug

    $self->validity_periods($restricted_periods->get_periods);
}

sub covers_period {
    my ($self, $period, $grace_period_seconds) = @_;

    $grace_period_seconds //= 0;

    for my $this_period (@{$self->get_periods}) {
        if ( ($this_period->get_notbefore_ts <= $period->get_notbefore_ts + $grace_period_seconds)
            and ($this_period->get_notafter_ts + $grace_period_seconds >= $period->get_notafter_ts)
        )
        {
            return 1;
        }
    }

    return 0;
}

sub get_earliest_period {
    my $self = shift;

    my $periods = $self->get_periods;
    if (scalar @$periods > 0) {
        my @ordered_periods = sort {$a->get_notbefore_ts <=> $b->get_notbefore_ts} @{$periods};
        return $ordered_periods[0];
    } else {
        return undef;
    }
}

sub starts_earlier_than {
    # $periods must be a CertReader::CA::ValidityPeriods
    my ($self, $periods, $grace_period_seconds) = @_;
    $grace_period_seconds //= 0;

    my $this_earliest_period = $self->get_earliest_period;
    my $other_earliest_period = $periods->get_earliest_period;

    if (not defined($other_earliest_period)) {
        return 1;
    }
    if (not defined($this_earliest_period)) {
        return 0;
    }

    if ($this_earliest_period->get_notbefore_ts < $other_earliest_period->get_notbefore_ts + $grace_period_seconds) {
        return 1;
    } else {
        return 0;
    }

}

sub to_string {
    my $self = shift;

    my $str = "";
    my $first = 1;
    for my $period (sort {$a->get_notbefore_ts <=> $b->get_notbefore_ts} @{$self->get_periods}) {
        if (not $first) {
            $str .= ' ;; ';
        } else {
            $first = 0;
        }
        my $start = $period->get_notbefore;
        my $end = $period->get_notafter;
        $str .= "$start - $end";
    }

    return $str;
}



package CertReader::CA::ValidityPeriods::ValidityPeriod;

use 5.16.1;

use strict;
use warnings;
use Carp;

use Moose;

use Date::Parse;

has 'not_before' => (
    is => 'rw',
    isa => 'Str | Undef',
    required => 1,
    default => undef,
);

has 'not_after' => (
    is => 'rw',
    isa => 'Str | Undef',
    required => 1,
    default => undef,
);

sub get_notbefore {
    return shift->not_before;
}

sub get_notbefore_ts {
    return str2time(shift->get_notbefore, "GMT");
}

sub get_notafter {
    return shift->not_after;
}

sub get_notafter_ts {
    return str2time(shift->get_notafter, "GMT");
}

sub set_notbefore {
    my ($self, $not_before) = @_;
    $self->not_before($not_before);
}

sub set_notafter {
    my ($self, $not_after) = @_;
    $self->not_after($not_after);
}

1;
