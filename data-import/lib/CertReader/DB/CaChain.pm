package CertReader::DB::CaChain;

use 5.14.1;
use strict;
use warnings;

use Carp;
use autodie;

use CertReader::DB;
use CertReader::CA::Chain;

use base qw/CertReader::DB::Object/;

__PACKAGE__->meta->setup
(
    table => 'ca_chain',
    columns => [
        id => { type => 'bigserial', },
        store => { type => 'integer', not_null => 1 },
        path => { type => 'string', not_null => 1 },
        chain_len => { type => 'integer', not_null => 1 },
        # TODO instead of leaf_subject_md5, better use a ca_id as done by crt.sh
        leaf_subject_md5 => { type => 'char', length => 32 },
        added_to_db => { type => 'varchar', length => 255, not_null => 1},
  ],
    pk_columns => 'id',

    relationships => [
        rootstore => {
            type => 'many to one',
            class => 'CertReader::DB::RootCerts',
            column_map => { store => 'id' },
        },
    ],
);

sub cert_ids {
    my $self = shift;

    if (defined $self->{'cert_ids'}) {
        return $self->{'cert_ids'};
    }

    my $cert_ids = [];
    for my $id (split(/\./, $self->path)) {
        push(@$cert_ids, $id);
    }

    $self->{'cert_ids'} = $cert_ids;
    return $self->{'cert_ids'};
}

sub contains_cert {
    my ($self, $cert) = @_;

    for my $chain_cert_id (@{$self->cert_ids}) {
        if ($chain_cert_id == $cert->id) {
            return 1;
        }
    }

    return 0;
}




#__PACKAGE__->meta->make_manager_class('cachains');

package CertReader::DB::CaChain::Manager;

use base 'Rose::DB::Object::Manager';

use Digest::MD5 qw/md5_hex/;
use Encode qw/encode_utf8/;
use Date::Format;


sub object_class { 'CertReader::DB::CaChain' }

__PACKAGE__->make_manager_methods('cachains');

sub get_cachains_from_sql {
    shift->get_objects_from_sql(@_, object_class => 'CertReader::DB::CaChain');
}

sub get_cachains_iterator_from_sql {
    shift->get_objects_iterator_from_sql(@_, object_class => 'CertReader::DB::CaChain');
}

sub test_if_cachain_exists {
    my ($cls, $rid, $path, $leafcert) = @_;
    my $postfix = 'full';  # TODO hardcoded, should be obtained from somewhere

    my $cachains = $cls->get_cachains_from_sql(
        db => $leafcert->db,
        inject_results => 1,
        sql => "select * from ca_chain_$postfix where store = $rid and path = '$path';",
    );

    my $cachain_cnt = scalar @$cachains;
    if ($cachain_cnt > 1) {
        croak("Found multiple cachains for rid $rid, path $path");
    }

    if ($cachain_cnt) {
        my $cachain = shift @$cachains;
        return $cachain->id;
    } else {
        return 0;
    }

}

sub _cert_field_md5 {
    my ($self, $fieldvalue) = @_;
    return md5_hex(encode_utf8($fieldvalue));
}

sub _cert_subject_md5 {
    # return the cert's md5(subject) as used to create and retrieve ca_chain objects
    my ($self, $cert) = @_;
    return $self->_cert_field_md5($cert->subject);
}

sub _cert_issuer_md5 {
    # return the cert's md5(issuer) as used to create and retrieve ca_chain objects
    my ($self, $cert) = @_;
    if (defined $cert->{'_cachain_set_md5_issuer'}) {
        return $cert->{'_cachain_set_md5_issuer'};
    }

    $cert->{'_cachain_set_md5_issuer'} = $self->_cert_field_md5($cert->issuer);
    return $cert->{'_cachain_set_md5_issuer'};
}

sub db_add_cachain {
    my ($cls, $chain, $leafcert) = @_;

    my $rid = $chain->rid;
    my $path = join('.', @{$chain->cert_ids});

    my $id = $cls->test_if_cachain_exists($rid, $path, $leafcert);

    if ($id) {
        return $id;
    } else {
        my $cachain = CertReader::DB::CaChain->new(
            store => $rid,
            path => $path,
            chain_len => $chain->length,
            leaf_subject_md5 => $cls->_cert_subject_md5($leafcert),
            added_to_db => time2str("%Y-%m-%d %H:%M:%S", time, "UTC"),
        );
        $cachain->save;
        return $cachain->id;
    }
}

sub get_cachains_count_for_issuer_md5 {
    my ($cls, $rid, $issuer_md5, $chain_len) = @_;

    my $cnt;
    if (defined $chain_len) {
        $cnt = $cls->get_cachains_count(
            query =>[
                store => $rid,
                leaf_subject_md5 => $issuer_md5,
                chain_len => $chain_len,
            ]
        );
    } else {
        $cnt = $cls->get_cachains_count(
            query =>[
                store => $rid,
                leaf_subject_md5 => $issuer_md5,
            ]
        );
    }

    return $cnt;
}

sub get_cachains_for_issuer_md5 {
    my ($cls, $rid, $issuer_md5, $chain_len, $db, $order_by_id_asc) = @_;
    my $postfix = 'full';  # TODO hardcoded, should be obtained from somewhere
    $order_by_id_asc //= 0;

    my $sql = "select * from ca_chain_$postfix where store = $rid and leaf_subject_md5 = '$issuer_md5'";
    if (defined($chain_len)) {
        $sql .= " and chain_len = $chain_len";
    }
    if ($order_by_id_asc) {
        $sql .= " order by id asc";
    }
    $sql .= ";";
    my $cachains = $cls->get_cachains_from_sql(
        db => $db,
        inject_results => 1,
        sql => $sql,
    );

    return $cachains;
}

sub get_cachains_count_for_cert {
    my ($cls, $rid, $cert, $chain_len) = @_;
    my $issuer_md5 = $cls->_cert_issuer_md5($cert);

    return $cls->get_cachains_count_for_issuer_md5($rid, $issuer_md5, $chain_len);
}

sub cert_is_leaf_of_count_cachains {
    my ($cls, $rid, $cert, $count) = @_;
    my $postfix = 'full';  # TODO hardcoded, should be obtained from somewhere

    # TODO can we realize this with get_cachains_count?

    my $cert_subject_md5 = $cls->_cert_subject_md5($cert);
    my $cert_id = $cert->id;

    my $sql = "select * from ca_chain_$postfix where store = $rid and leaf_subject_md5 = '$cert_subject_md5'";
    $sql .= " and (CASE WHEN nlevel(path) > 0 THEN ltree2text(subpath(path, 0, 1))::int = $cert_id ELSE false END)";  # note: ca_chain path starts with the leaf
    $sql .= " LIMIT $count";
    $sql .= ";";
    my $cachains = $cls->get_cachains_from_sql(
        db => $cert->db,
        inject_results => 1,
        sql => $sql,
    );
    my $found_cachains_cnt = scalar @$cachains;
    if ($found_cachains_cnt >= $count) {
        return 1;
    }
    return 0;
}

sub get_cachains_for_cert {
    my ($cls, $rid, $cert, $chain_len, $order_by_id_asc) = @_;
    $order_by_id_asc //= 0;

    my $issuer_md5 = $cls->_cert_issuer_md5($cert);
    return $cls->get_cachains_for_issuer_md5($rid, $issuer_md5, $chain_len, $cert->db, $order_by_id_asc);
}


sub get_cachain_iterator_for_issuer_md5 {
    my ($cls, $rid, $issuer_md5, $chain_len, $db, $order_by_id_asc) = @_;
    my $postfix = 'full';  # TODO hardcoded, should be obtained from somewhere
    $order_by_id_asc //= 0;

    my $sql = "select * from ca_chain_$postfix where store = $rid and leaf_subject_md5 = '$issuer_md5'";
    if (defined($chain_len)) {
        $sql .= " and chain_len = $chain_len";
    }
    if ($order_by_id_asc) {
        $sql .= " order by id asc";
    }
    $sql .= ";";
    my $cachain_it = $cls->get_cachains_iterator_from_sql(
        db => $db,
        inject_results => 1,
        sql => $sql,
    );

    return $cachain_it;
}

sub get_cachains_iterator_for_cert {
    my ($cls, $rid, $cert, $chain_len, $order_by_id_asc) = @_;

    my $issuer_md5 = $cls->_cert_issuer_md5($cert);
    return $cls->get_cachain_iterator_for_issuer_md5($rid, $issuer_md5, $chain_len, $cert->db, $order_by_id_asc);
}


1;
