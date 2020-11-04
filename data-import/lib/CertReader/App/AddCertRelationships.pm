package CertReader::App::AddCertRelationships;

use 5.14.1;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Scalar::Util;

use Moose;

use FileHandle;
use List::Util qw[min max];

use Crypt::OpenSSL::X509;

use CertReader::DB::CAactor;
use CertReader::DB::CertificateRelation;
use CertReader::DB::CArelation;
use CertReader::DB::RootCerts;
use CertReader::DB::Certificate;
with 'CertReader::Base';
with 'CertReader::CA';
with 'CertReader::CertCache';

my $stepsize = 10000;

has 'ignore_known_certs' => (
    is => 'rw',
    isa => 'Bool',
    required => 1,
    default => 0,
    documentation => 'Ignore certificates that already have a Certificate relation.',
);

has 'root_only' => (
    is => 'rw',
    isa => 'Bool',
    required => 1,
    default => 0,
    documentation => 'Ignore intermediate certificates. Default: Handle root and (valid) intermediate certificates',
);

has 'auto_select_cas' => (
    is => 'rw',
    isa => 'Bool',
    required => 1,
    default => 0,
    documentation => 'Automatically select the CA based on a substring comparison of known CAs and the certificate\'s subject',
);

has 'disable_certificate_relations_sanity_check' => (
    is => 'rw',
    isa => 'Bool',
    required => 1,
    default => 0,
    documentation => '',
);

has 'start_with_certid' => (
    is => 'rw',
    isa => 'Int',
    required => 0,
    default => 0,
    documentation => "Skip all certificates with id smaller than given. Usually only needed to resume work.",
);

has 'ignore_validity' => (
    is => 'rw',
    isa => 'Bool',
    required => 0,
    default => 0,
    documentation => "Do not skip invalid certificates",
);

has 'stepsize' => (
    is => 'rw',
    isa => 'Int',
    required => 1,
    default => $stepsize,
    documentation => "Maximum number of lines requested from the database in one query. Default: $stepsize",
);

sub run {
    my $self = shift;
    my $postfix = $self->tablepostfix;

    $self->update_ca_actor_list;

    STDOUT->autoflush(1);
    STDERR->autoflush(1);

    $self->add_certificate_relations;
    $self->certificate_relations_sanity_check;
    $self->backup_ca_actors;

}


sub add_certificate_relations {
    my $self = shift;
    my $postfix = $self->tablepostfix;

    my $certid_max = CertReader::DB::Certificate::Manager->get_certificate_id_max($self->db, $self->tablepostfix);
    my $currid = 0;
    my $lastid = -1;
    if ($self->start_with_certid) {
        $currid = $self->start_with_certid;
    }
    while( $lastid < $certid_max ) {
        $lastid = min($currid + ($stepsize - 1), $certid_max);

        my $sql;
        if ($self->root_only) {
            $sql = "select cert.* from root_certs_$postfix as root join certificate_$postfix as cert on root.certificate = cert.id order by root.id asc;";
            $lastid = $certid_max;  # we process all valid root certs in one go
        } else {
            $sql = "select * from certificate_$postfix as cert where id >= $currid and id <= $lastid and ca = True";
            if ($self->ignore_validity) {
                ;
            } else {
                $sql .= " and (select count(*) from verify_tree_$postfix as vts where vts.certificate = cert.id limit 1) > 0";
            }
            $sql .= " order by id asc;";
        }

        $currid = $lastid + 1;

        my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
            db => $self->db,
            inject_results => 1,
            sql => $sql,
        );

        while (my $cert = $certiter->next) {
            $self->add_certificate_relation_for_cert($cert);
        }

    }

}

sub certificate_relations_sanity_check {
    my $self = shift;
    my $postfix = $self->tablepostfix;

    if ($self->disable_certificate_relations_sanity_check) {
        say "WARNING: Skipping sanity check!";
        return;
    }

    $self->auto_select_cas(0);
    $self->ignore_known_certs(0);

    say "Starting sanity checking of certificate relations...";
    my $ca_actor_it = CertReader::DB::CAactor::Manager->get_caactors_iterator_from_sql(
        db => $self->db,
        inject_results => 1,
        sql => "select * from ca_actor_$postfix order by name",
    );
    while (my $ca_actor = $ca_actor_it->next) {

        my $ca_actor_name_len = (length $ca_actor->name);
        if ($ca_actor_name_len < 20) {
            my $ok = 0;
            while (!$ok) {
                say "\nCAactor \"" . $ca_actor->name . "\" has a short name ($ca_actor_name_len characters), double check certificate subjects:";
                my $sql = "select cert.* from (select * from certificate_relation_$postfix as cr where cr.owner_id = " . $ca_actor->id . ") as crs join certificate_$postfix as cert on crs.certificate_id = cert.id order by cert.id;";
                my $certs = ();
                my $certs_index = 0;
                my $certiter = CertReader::DB::Certificate::Manager->get_certificates_iterator_from_sql(
                    db => $self->db,
                    inject_results => 1,
                    sql => $sql,
                );
                while (my $cert = $certiter->next) {
                    say "\t$certs_index: Certificate " . $cert->id  . "  \t" . $cert->subject;
                    push @$certs, $cert;
                    $certs_index += 1;
                }

                print "Press Enter to advance or enter number of cert to correct...";
                my $user_in = <STDIN>;
                chomp $user_in;
                if ($user_in eq "") {
                    $ok = 1;
                } else {
                    $self->add_certificate_relation_for_cert(@$certs[int($user_in)])
                }
            }
        }

    }
}

sub add_certificate_relation_for_cert {
    my ($self, $cert) = @_;

    say "Certificate " . $cert->id . ": ";

    my $cert_relation = CertReader::DB::CertificateRelation->new(db => $self->db, 'certificate_id' => $cert->id);
    my $cert_relation_exists = $cert_relation->load(use_key => 'certificate_id', speculative => 1);
    my $owner;
    if ($cert_relation_exists) {
        if ($self->ignore_known_certs) {
            say "\tCert relation already set: skipping";
            return;
        }

        $owner = CertReader::DB::CAactor->new(db => $self->db, 'id' => $cert_relation->owner_id);
        $owner->load();
    } else {
        ;
    }

    say "\tSubject: " . $cert->subject;
    my $owner_string = '<undef>';
    $owner_string = $owner->name if $owner;
    say "\tcurrent owner: $owner_string";
    say "\tSuggestions: ";
    my $suggestions = ();
    my $suggestions_index = 0;
    my $suggestions_are_existing_ca_actors = 0;
    foreach (@{$self->{ca_actors}}) {
        # Find matching known CA actors by checking if the CA actors's name
        # occurs in the certificates subject
        if (index(lc $cert->subject, lc $_) != -1) {
            push @$suggestions, $_;
            say "\t\t$suggestions_index: " . $_;
            $suggestions_index += 1;
            $suggestions_are_existing_ca_actors = 1;
        }
    }
    if ($suggestions_index == 0) {
        # Cert seems not to belong to a already known CA, come up with a good
        # suggestion for the new CA actor
        my $organisation = $cert->subject;
        $organisation = (split("O=", $organisation, 2))[1] if $organisation;
        $organisation = (split(",", $organisation, 2))[0] if $organisation;
        push @$suggestions, $organisation if $organisation;
        say "\t\t$suggestions_index: " . $organisation . " (new)" if $organisation;
    }
    my $new_owner_string;
    if ($self->auto_select_cas and $suggestions_are_existing_ca_actors and $suggestions_index == 1) {
        say "\tAutomatically selecting the single matching existing CA actor as owner";
        $new_owner_string = @$suggestions[0];
    } else {
        print "\tPlease enter owner name (<Enter>: Suggestion '0', <num>: Suggestion, -1: keep): ";
        my $user_in = <STDIN>;
        chomp $user_in;

        if (Scalar::Util::looks_like_number($user_in)) {
            $user_in = int($user_in);
            if ($user_in == -1) {
                say "\tKeeping current owner ($owner_string)";
                return;
            } else {
                $new_owner_string = @$suggestions[$user_in];
            }
        } else {
    if ($user_in eq "") {
        $new_owner_string = @$suggestions[0];
    } else {
                $new_owner_string = $user_in;
        }
        }
    }
    my $ca_actor = $self->get_ca_actor($new_owner_string);
    $cert_relation->owner_id($ca_actor->id);
    $cert_relation->save;
    say "\tOwner set to " . $ca_actor->name . " (id: " . $ca_actor->id . ")";

    say "";
}

sub update_ca_actor_list {
    my $self = shift;
    my $postfix = $self->tablepostfix;
    
    my $ca_actor_it = CertReader::DB::CAactor::Manager->get_caactors_iterator_from_sql(
        db => $self->db,
        inject_results => 1,
        sql => "select * from ca_actor_$postfix order by id",
    );
    my $ca_actors = ();
    while (my $ca_actor = $ca_actor_it->next) {
        push @$ca_actors, $ca_actor->name;
    }
    $self->{ca_actors} = $ca_actors;
}

sub get_ca_actor {
    my ($self, $caactor_name) = @_;

    my $test = CertReader::DB::CAactor->new(db => $self->db, 'name' => $caactor_name);
    if (! $test->load(use_key => 'name', speculative => 1)) {
        $test->save;
        $self->update_ca_actor_list;
    }

    return $test;

    # my $csc = CertReader::DB::CAactor::Manager->get_caactor_for_($self->db, $self->tablepostfix, $cert);
    # if (!$csc) {
    #     $csc = CertReader::DB::CrossSignCandidate->new(
    #         subject => $cert->subject,
    #         key_mod => $cert->key_mod,
    #         );
    #     $csc->save;
    #     if ($self->debug_csc_preprocessing) {
    #         say "\t\tnew csc id: " . $csc->id;
    #         say "\t\t\tsubject: " . $cert->subject;
    #         say "\t\t\tkey_mod: " . $cert->key_mod;
    #     }
    # }
}

sub backup_ca_actors {
    my $self = shift;
    my $postfix = $self->tablepostfix;

    my $addcaactors_file = "./lib/CertReader/App/AddCAactors.pm";
    my $fh = FileHandle->new($addcaactors_file, '>:encoding(UTF-8)');
    if (!defined($fh)) {
        # Might have been started in local directory
        # TODO poor mans solution
        $addcaactors_file = "./AddCAactors.pm";
        $fh = FileHandle->new($addcaactors_file, '>:encoding(UTF-8)');
    }
    croak("Could not open $addcaactors_file") if !defined($fh);
    $fh->autoflush(1);

    my $ca_actor_it = CertReader::DB::CAactor::Manager->get_caactors_iterator_from_sql(
        db => $self->db,
        inject_results => 1,
        sql => "select * from ca_actor_$postfix order by name",
    );

    my $header = qq{# WARNING this file is autogenerated by CertReader::App::AddCertRelationships

package CertReader::App::AddCAactors;

# application to add CAactors to the database

use 5.14.1;
use strict;
use warnings;

use Moose;
with 'MooseX::Getopt';
with 'MooseX::Runnable';
with 'CertReader::ORM';

sub run \{
    my \$self = shift;
    my \$postfix = \$self->tablepostfix;

    my \@commands;

};

    say $fh $header;

    while (my $ca_actor = $ca_actor_it->next) {
        say $fh "    push (\@commands, <<END);";
        say $fh "    " . $ca_actor->to_insert_statement;
        say $fh "END";
        say $fh "";
    }

    my $footer = qq {
    # Execute commands
    for my \$command ( \@commands ) \{
        say \"Executing \$command\";
        my \$sth = \$self->db->dbh->prepare(\$command);
        \$sth->execute;
    \}

\}

1;
};
    say $fh $footer;

}


1;
