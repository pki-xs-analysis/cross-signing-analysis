#!/usr/bin/env bash

psql -p 7779 -d notary -c 'DELETE FROM verify_tree_full';
psql -p 7779 -d notary -c 'ALTER SEQUENCE verify_tree_full_id_seq RESTART WITH 1';


# We deleted all validity bits, i.e., also those that mark root certs as valid for themselves
# TODO speed up achievable by simply setting the valid bit correctly.
psql -p 7779 -d notary -c 'DELETE FROM root_certs_full';
psql -p 7779 -d notary -c 'ALTER SEQUENCE root_certs_full_id_seq RESTART WITH 1';
source readroots.sh

