#!/usr/bin/env bash
#
# Install all needed prerequisites from a "clean" perl installation
#
# Please create a directory ${PERLCRYPT} and check out:
# export BASEDIR=~
# export PERLCRYPT=$BASEDIR/crypt/
# mkdir $PERLCRYPT
# git clone https://github.com/0xxon/alien-openssl $PERLCRYPT/alien-openssl
# git clone https://github.com/0xxon/perl-crypt-openssl-x509 $PERLCRYPT/perl-crypt-openssl-x509
# before running this script
#
# It is adviseable to have a installation of perl separately from the operating system
# installation before attempting all of this.
#
# Use the most current perl version from http://www.cpan.org/src/, e.g.,
# wget https://www.cpan.org/src/5.0/perl-5.28.1.tar.gz
# tar -xzf perl-5.28.1.tar.gz
# export PERLDIR=$BASEDIR/localperl
# cd perl-5.28.1
# ./Configure -des -Dusethreads -Dprefix=$PERLDIR
# make
# make test
# make install
# cd ..
#
# If not already installed - install postgres _and_ development headers.
# Install the latest postgresql version for best performance (optional)
# Get the most current postgresql version from https://www.postgresql.org/ftp/source/, e.g.,
# wget https://ftp.postgresql.org/pub/source/v11.1/postgresql-11.1.tar.gz
# tar -xzf postgresql-11.1.tar.gz
# export POSTGRES=$BASEDIR/localpostgresql
# cd postgresql-11.1
# ./configure --with-openssl --prefix=$POSTGRES
# make world
# make check
# make install-world
#
# Make sure to always use the just compiled perl and postgres versions:
# echo "export PATH=$PERLDIR/bin:\$PATH" >> $HOME/.bashrc
# echo "export PATH=$POSTGRES/bin:\$PATH" >> $HOME/.bashrc
#
# After installation, you have to patch Rose/DB.pm in your site_perl folder.
# This file should reside in $PERL/lib/site_perl/[perl-version-number]/Rose/DB.pm
# For me, this is /Users/johanna/sw/lib/perl5/site_perl/5.24.1/Rose/DB.pm
# If the file does not exist, install the module Rose::DB:
# cpan install Rose::DB
#
# Change around line 1860 from
#
# sub format_bitfield
# {
#   my($self, $vec, $size) = @_;
#
#   if($size)
#   {
#     $vec = Bit::Vector->new_Bin($size, $vec->to_Bin);
#     return sprintf('%0*b', $size, hex($vec->to_Hex));
#   }
#
#   return sprintf('%b', hex($vec->to_Hex));
# }
#
# to
#
# sub format_bitfield
# {
#   my($self, $vec, $size) = @_;
#
#   if($size)
#   {
#     $vec = Bit::Vector->new_Bin($size, $vec->to_Bin);
#     return $vec->to_Bin;
#   }
#
#   return sprintf('%b', hex($vec->to_Hex));
# }
#
#


# If you do this on Ubuntu (and maybe other distros than Fedora 28 with OpenSSL 1.1.0i-fips)
# we need to build openssl and set OPENSSL_PREFIX when installing Net::SSLeay
# (which is required by LWP::Protocol::https).
#
# export OPENSSLDIR=$PERLCRYPT/openssl
# cd $PERLCRYPT
# wget https://www.openssl.org/source/openssl-1.1.0i.tar.gz
# tar -xzf openssl-1.1.0i.tar.gz
# cd openssl-1.1.0i
# ./config shared --prefix=$OPENSSLDIR --openssldir=$OPENSSLDIR
# make depend
# make
# make test
# make install
# OPENSSL_PREFIX=$OPENSSLDIR cpan install Net::SSLeay
# # For some unknown reason, on Ubuntu, this installs SSLeay files to lib/perl5 instead
# # of lib/site_perl. We need to tell cpan that there is a new directory to look at.
# # Note that perl automatically adds the x86_64-linux-thread-multi subdir for entries
# # in PERL5LIB (cf. perl -V), but cpan does not (cf. cpan -V), hence we also add the
# # subdirectory here
# # Remember that you probably want to add this to your .bashrc or similar
# export PERL5LIB=$PERLDIR/lib/perl5:$PERLDIR/lib/perl5/x86_64-linux-thread-multi
#


cpan install Alien::Base
cpan install Alien::Base::ModuleBuild
#cpan install Alien::Build
cpan install Cache::Memcached
cpan install DBD::Pg
cpan install Class::Load
cpan install Pg::hstore
cpan install Number::Format
cpan install Template::Plugin::JSON::Escape
cpan install Digest::SHA1
cpan install JSON
cpan install JSON::XS
cpan install Bro::Log::Parse
cpan install YAML
cpan install YAML::XS
cpan install Perl6::Slurp
cpan install Date::Parse
cpan install Carp::Assert
cpan install Module::Install
cpan install Sort::Versions
cpan install Text::Template
cpan install Moose
cpan install MooseX::Runnable
cpan install Rose::DB::Object
cpan install Math::BigInt::GMP
cpan install DateTime::Format::ISO8601
cpan install Getopt::ArgParse
cpan install Switch
cpan install Text::CSV
cpan install forks
cpan install Forks::Queue
cpan install Cpanel::JSON::XS
cpan install LWP::Protocol::https
cpan install Scalar::Util
cpan install Array:Utils

#pushd $PERLCRYPT/alien-openssl
#perl Build.PL
#export ALIEN_FORCE=1
#./Build distclean
#perl Build.PL --version 1.0.2k
#./Build
#./Build test
#./Build install
#popd

pushd $PERLCRYPT/alien-openssl
rm -rf _alien
rm -rf blib
export ALIEN_INSTALL_TYPE=share
export KERNEL_BITS=64
perl Makefile.PL --version 1.0.2o
make
make test
make install
popd

pushd $PERLCRYPT/perl-crypt-openssl-x509
perl Makefile.PL
make distclean
perl Makefile.PL
# Now there is a tricky part:
# If you look at the created `Makefile` you can find the variable LDDLFLAGS
# This most probably adds directories for the linker, e.g., -L/usr/local/lib
# Similarly EXTRALIBS and LDLOADLIBS add the paths where alien-openssl was installed
# before linking to libssl and libcrypto. We want the compilation to use these alien-openssl
# libraries. However, the compile command adds $LDDFLAGS before $LDLOADLIBS.
# Hence, if $LDDFLAGS adds a directory that already contains libssl or libcrypto,
# which is the case on Ubuntu -- specifically /usr/local/lib -- (and possibly other
# distros than Fedora), our compilation does not use the libraries located in the
# directories added by $LDLOADLIBS.
# The quick fix is to edit the Makefile such that it includes the desired directory
# already with the $LDDFLAGS. For me that looked like follows:
# LDDLFLAGS = -shared -O2 -L/opt/localperl/lib/site_perl/5.28.1/x86_64-linux-thread-multi/auto/share/dist/Alien-OpenSSL/lib -L/usr/local/lib -fstack-protector-strong
make
make test
# It is ok if `make test` returns the following error for verifychain.t.
# But all other test must pass! The output should look similar to this:
#
# t/00-version.t ... # Running Crypt::OpenSSL::X509 test suite against OpenSSL 1.1.0i  14 Aug 2018 (Library: OpenSSL 1.1.0g  2 Nov 2017)
# t/00-version.t ... ok
# t/pod.t .......... ok
# t/utf8.t ......... ok
# t/verify.t ....... ok
# t/verifychain.t .. 1/17
# #   Failed test 'Selfsigned certificate invalid'
# #   at t/verifychain.t line 24.
# #          got: undef
# #     expected: '-18'
# # Looks like you failed 1 test of 17.
# t/verifychain.t .. Dubious, test returned 1 (wstat 256, 0x100)
# Failed 1/17 subtests
# t/x509-ec.t ...... ok
# t/x509.t ......... ok
#
# Test Summary Report
# -------------------
# t/verifychain.t (Wstat: 256 Tests: 17 Failed: 1)
#   Failed test:  6
#   Non-zero exit status: 1
# Files=7, Tests=106,  1 wallclock secs ( 0.06 usr  0.01 sys +  0.45 cusr  0.07 csys =  0.59 CPU)
# Result: FAIL
# Failed 1/7 test programs. 1/106 subtests failed.
# Makefile:966: recipe for target 'test_dynamic' failed
# make: *** [test_dynamic] Error 255
make install
popd
