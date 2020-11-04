package CertReader::App::AddCArelationships;

use 5.14.1;
use strict;
use warnings;

use Carp;
use Data::Dumper;
use Scalar::Util;

use Moose;

use Crypt::OpenSSL::X509;

use CertReader::DB::CAactor;
use CertReader::DB::CertificateRelation;
use CertReader::DB::CArelation;
use CertReader::DB::RootCerts;
use CertReader::DB::Certificate;
with 'CertReader::Base';
with 'CertReader::CA';
with 'CertReader::CertCache';

sub run {
    my $self = shift;
    my $postfix = $self->tablepostfix;

    add_carelation($self, 'Equifax', 'GeoTrust', 'owned_by', '2001-01-01 00:00:00');  # https://en.wikipedia.org/wiki/GeoTrust

    add_carelation($self, 'thawte', 'VeriSign', 'owned_by', '1999-01-01 00:00:00');    # 1999  https://en.wikipedia.org/wiki/Thawte
    add_carelation($self, 'GeoTrust', 'VeriSign', 'owned_by', '2006-09-01 00:00:00');  # 09-2006  https://en.wikipedia.org/wiki/GeoTrust
    add_carelation($self, 'RapidSSL', 'GeoTrust', 'owned_by', '1970-01-01 00:00:00'); # https://www.rapidssl.com/about/

    add_carelation($self, 'VeriSign', 'Symantec', 'owned_by', '2010-08-01 00:00:00');  # 08-2010  https://en.wikipedia.org/wiki/Thawte

    add_carelation($self, 'Symantec', 'DigiCert', 'owned_by', '2017-08-04 00:00:00');  # 2017  https://en.wikipedia.org/wiki/DigiCert ; https://www.digicert.com/news/digicert-to-acquire-symantec-website-security-business/
    add_carelation($self, 'GTE Corporation', 'Verizon', 'owned_by', '1970-01-01 00:00:00'); # https://en.wikipedia.org/wiki/GTE
    add_carelation($self, 'GTE Corporation', 'Digicert', 'owned_by', '2015-06-23 00:00:00'); # https://www.digicert.com/news/2015-06-23-digicert-acquires-verizon-business/; https://www.digicert.com/digicert-root-certificates.htm
    add_carelation($self, 'Cybertrust', 'Verizon', 'owned_by', '2007-01-01 00:00:00'); # 2007 https://en.wikipedia.org/wiki/CyberTrust
    add_carelation($self, 'Cybertrust', 'DigiCert', 'owned_by', '2015-06-23 00:00:00');  # 2015  https://en.wikipedia.org/wiki/DigiCert ; https://www.digicert.com/news/2015-06-23-digicert-acquires-verizon-business/
    # "The acquisition of the CyberTrust root certificates makes DigiCert the second-largest Certificate Authority (CA) for high-assurance SSL Certificates. As part of the deal, DigiCert will assume management of the CyberTrust/Verizon trusted roots and intermediate certificates. Verizon will continue to offer SSL Certificates as a reseller of DigiCert. https://www.digicert.com/news/2015-06-23-digicert-acquires-verizon-business/"
    add_carelation($self, 'Cybertrust Japan', 'Cybertrust', 'owned_by', '2017-01-01 00:00:00');  # 2017 https://www.cybertrust.co.jp/english/
    add_carelation($self, 'DigiCert', 'DigiCert', 'owned_by', '1970-01-01 00:00:00');
    # add_carelation($self, 'DigiCert', 'Thoma Bravo', 'owned_by', '2015-10-22 00:00:00');  # https://www.thomabravo.com/press-releases/thoma-bravo-completes-acquisition-of-majority-stake-in-digicert
    add_carelation($self, 'DigiCert-Grid', 'DigiCert-Grid', 'owned_by', '1970-01-01 00:00:00'); # Grid part if digicert, leave separate as it bridges
    # Digicert 'Partner and GeoTrust Retail Competitive Replacement': Targets "competitors": GlobalSign, Comodo, GoDaddy, Entrust, Baltimore, Microsoft, SECOM, Polish CA Cetrum, USER Trust - Comodo's White Label Root, or DigiNotar
    # https://knowledge.digicert.com/solution/SO9268.html

    add_carelation($self, 'Digicert Sdn', 'Digicert Sdn', 'owned_by', '1970-01-01 00:00:00'); # https://www.digicert.com/news/2011-11-1-breaches-and-similar-names/

    add_carelation($self, 'QuoVadis', 'WISeKey', 'owned_by', '2017-01-01 00:00:00');  # 2017  https://www.quovadisglobal.com/AboutUs.aspx
    add_carelation($self, 'QuoVadis', 'DigiCert', 'owned_by', '2019-01-01 00:00:00');  # 2019  https://www.quovadisglobal.com/AboutUs.aspx

    add_carelation($self, 'USERTRUST', 'COMODO', 'owned_by', '1970-01-01 00:00:00');
    add_carelation($self, 'ScandTrust', 'AddTrust', 'owned_by', '1970-01-01 00:00:00'); # ???
    # AddTrust external Root will phase out and be replaced by Comodo RSA Certification Authority (May 2020); Sectigo uses cross-signing
    add_carelation($self, 'AddTrust', 'COMODO', 'owned_by', '1970-01-01 00:00:00');
    add_carelation($self, 'Positive Software Corporation', 'COMODO', 'owned_by', '2005-01-24 00:00:00'); # https://www.comodo.com/news/press_releases/24_01_05.html
    # Comodo rebranded as Sectigo (14.01.2019); --> new chain of intermediates
    add_carelation($self, 'COMODO', 'Sectigo', 'owned_by', '2018-01-01 00:00:00');
    add_carelation($self, 'OptimumSSL', 'Sectigo', 'owned_by', '2018-01-01 00:00:00'); # optimumssl.com links to https://sectigo.com/

    add_carelation($self, 'Serasa', 'Experian', 'owned_by', '2007-01-01 00:00:00'); # 2007 https://translate.google.com/translate?sl=auto&tl=en&u=https%3A%2F%2Fpt.wikipedia.org%2Fwiki%2FSerasa_Experian

    add_carelation($self, 'GoGetSSL', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # see cert 163404675: C=LV, L=Riga, O=GoGetSSL, OU=Controlled by COMODO CA exclusively for GoGetSSL, CN=GoGetSSL ECC EV CA
    add_carelation($self, 'SSL.com', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # See certificate 57719: 'C=US, O=SSL.com, OU=Controlled by COMODO exclusively for SSL.com, CN=SSL.com Premium EV CA'
    add_carelation($self, 'Globe Hosting', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # See certificate 159945: 'C=US, O=Globe Hosting, Inc., OU=Controlled by COMODO exclusively for Globe Hosting, Inc., OU=GlobeSSL EV Certification Authority, CN=GlobeSSL CA'
    add_carelation($self, 'Site Blindado S.A.', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # See certificate 257847: 'C=BR, ST=SP, L=Sao Paulo, O=Site Blindado S.A., OU=Controlled by COMODO exclusively for Site Blindado S.A., OU=Certificação Digital, CN=SSL Blindado EV'
    add_carelation($self, 'TrustSign Certificadora', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # See certificate 413644
    add_carelation($self, 'SecureCore', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # See certificate 166712866
    add_carelation($self, 'BlackCert', 'COMODO', 'reseller_of', '1970-01-01 00:00:00'); # see cert 181015283
    add_carelation($self, 'Verizon', 'DigiCert', 'reseller_of', '2015-01-01 00:00:00'); # https://www.digicert.com/news/2015-06-23-digicert-acquires-verizon-business/

    add_carelation($self, 'BlackCert', 'McAfee', 'owned_by', '1970-01-01 00:00:00'); # Blackcert was founded by John McAfee

    add_carelation($self, 'Sonera', 'TeliaSonera', 'owned_by', '2002-01-01 00:00:00'); # 2002 https://www.teliacompany.com/en/about-the-company/history/telia-sonera-and-teliasonera/
    add_carelation($self, 'Telia Finland', 'TeliaSonera', 'owned_by', '2002-01-01 00:00:00'); # 2002 https://www.teliacompany.com/en/about-the-company/history/telia-sonera-and-teliasonera/

    add_carelation($self, 'ValiCert', 'Starfield', 'owned_by', '2003-01-01 00:00:00'); # https://news.netcraft.com/archives/2004/03/12/go_daddy_now_an_ssl_certificate_authority.html
    add_carelation($self, 'Starfield', 'Go Daddy', 'owned_by', '1970-01-01 00:00:00'); # https://en.wikipedia.org/wiki/Starfield_Technologies
    add_carelation($self, 'Go Daddy', 'Go Daddy', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'AlphaSSL', 'GlobalSign', 'owned_by', '1970-01-01 00:00:00'); # powered by GlobalSign, but somewhat independent? https://www.alphassl.com/about.html
    add_carelation($self, 'GlobalSign', 'GlobalSign', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'StartCom', 'WoSign', 'owned_by', '2015-11-01 00:00:00'); # 11-2015  https://docs.google.com/document/d/1C6BlmbeQfn4a9zydVi2UvjBGv6szuSB4sMYUcVrR8vQ/edit#heading=h.h85tpg56x3q0    https://wiki.mozilla.org/CA:WoSign_Issues#Issue_R:_Purchase_of_StartCom_.28Nov_2015.29    https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/0pqpLJ_lCJQ
    add_carelation($self, 'WoSign', 'Qihoo', 'owned_by', '1970-01-01 00:00:00');

    # add_carelation($self, 'WoTrus', ''); # Rename of WoSign for reapplication, still owned by Qihoo
    add_carelation($self, 'WoTrus', 'DigiCert', 'reseller_of', '1970-01-01 00:00:00');
    add_carelation($self, 'WoTrus', 'Unizeto', 'reseller_of', '1970-01-01 00:00:00');
    add_carelation($self, 'WoTrus', 'Sectigo', 'reseller_of', '1970-01-01 00:00:00');
    # add_carelation($self, 'MeSince', 'WoTrus', 'owned_by', '1970-01-01 00:00:00'); # https://www.mesince.com/en-us/about

    add_carelation($self, 'T-Systems', 'Deutsche Telekom', 'owned_by', '1970-01-01 00:00:00');
    add_carelation($self, 'Deutsche Telekom', 'Deutsche Telekom', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'Let\'s Encrypt', 'Internet Security Research Group', 'owned_by', '1970-01-01 00:00:00');
    add_carelation($self, 'Internet Security Research Group', 'Internet Security Research Group', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'SwissSign', 'SwissSign', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'AffirmTrust', 'Entrust', 'owned_by', '2016-04-01 00:00:00'); # 04-2016  https://www.affirmtrust.com/about-us/
    add_carelation($self, 'Trend Micro', 'Entrust', 'owned_by', '2016-04-01 00:00:00'); # 04-2016  https://www.affirmtrust.com/about-us/
    # add_carelation($self, 'Entrust', 'Thoma Bravo', 'owned_by', '2009-07-29');  # https://www.thomabravo.com/press-releases/thoma-bravo-completes-124m-acquisition-of-entrust
    # add_carelation($self, 'Entrust', 'DataCard', 'owned_by', '2013-12-01');  # https://en.wikipedia.org/wiki/Entrust

    add_carelation($self, 'Digital Signature Trust', 'IdenTrust', 'owned_by', '2002-01-01 00:00:00'); # 2002  https://en.wikipedia.org/wiki/IdenTrust

    add_carelation($self, 'OpenTrust', 'KEYNECTIS', 'owned_by', '1970-01-01 00:00:00'); # 2011 https://www.businesswire.com/news/home/20110707005531/en/OpenTrust-Acquired-Keynectis https://bugzilla.mozilla.org/show_bug.cgi?id=1025095
    add_carelation($self, 'Certplus', 'KEYNECTIS', 'owned_by', '1970-01-01 00:00:00'); # https://bugzilla.mozilla.org/show_bug.cgi?id=1025095

    add_carelation($self, 'Certum', 'Unizeto', 'owned_by', '1970-01-01 00:00:00');
    add_carelation($self, 'SpaceSSL', 'Unizeto', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'UniTrust', 'SHECA', 'owned_by', '1970-01-01 00:00:00'); # http://codeverge.com/mozilla.dev.security.policy/sheca-root-inclusion-request/1506525
    add_carelation($self, 'SHECA', 'SHECA', 'owned_by', '1970-01-01 00:00:00'); # short for: Shanghai Electronic Certification Authority

    add_carelation($self, 'JanRain', 'Akamai', 'owned_by', '2019-01-01 00:00:00'); # 01-2019 https://en.wikipedia.org/wiki/Janrain

    add_carelation($self, 'C=ch, O=admin', 'Swiss Government', 'owned_by', '1970-01-01 00:00:00'); # bit.admin.ch  https://bugzilla.mozilla.org/show_bug.cgi?id=435026#c38
    add_carelation($self, 'DC=ch, DC=admin', 'Swiss Government', 'owned_by', '1970-01-01 00:00:00'); # bit.admin.ch  https://bugzilla.mozilla.org/show_bug.cgi?id=435026#c38
    add_carelation($self, 'The Federal Authorities of the Swiss Confederation', 'Swiss Government', 'owned_by', '1970-01-01 00:00:00'); # http://www.oecd.org/general/governmentofswitzerlandusefullinks.htm

    # add_carelation($self, 'SECOM', ''); # https://www.secomtrust.net/english/outline.html
    # add_carelation($self, 'Buypass', '');

    # add_carelation($self, 'Network Solutions', '?SAIC?'); # 1995  https://en.wikipedia.org/wiki/Network_Solutions
    add_carelation($self, 'Network Solutions', 'VeriSign', 'owned_by', '2000-01-01 00:00:00'); # 2000  https://en.wikipedia.org/wiki/Network_Solutions
    add_carelation($self, 'Network Solutions', 'Pivotal Equity Group', 'owned_by', '2003-10-17 00:00:00'); # 2003  https://en.wikipedia.org/wiki/Network_Solutions
    add_carelation($self, 'Network Solutions', 'General Atlantic', 'owned_by', '2007-02-01 00:00:00'); # 2007  https://en.wikipedia.org/wiki/Network_Solutions
    add_carelation($self, 'Network Solutions', 'web.com', 'owned_by', '2011-10-27 00:00:00'); # 2011  https://en.wikipedia.org/wiki/Network_Solutions

    add_carelation($self, 'Register.com', 'web.com', 'owned_by', '1970-01-01 00:00:00'); # https://www.register.com/about.rcmx

    add_carelation($self, 'SecureTrust', 'Trustwave', 'owned_by', '1970-01-01 00:00:00'); # https://securetrust.com/about-us/
    add_carelation($self, 'Trustwave', 'Sigtel', 'owned_by', '2015-04-08 00:00:00'); # https://en.wikipedia.org/wiki/Trustwave_Holdings

    add_carelation($self, 'TDC', 'TDC', 'owned_by', '1970-01-01 00:00:00'); # https://tdcgroup.com/en/who-we-are/history

    add_carelation($self, 'Autoridad de Certificacion Firmaprofesional CIF', 'Firmaprofesional S.A.', 'owned_by', '1970-01-01 00:00:00');

    add_carelation($self, 'U.S. Department of State AD', 'U.S. Government', 'owned_by', '1970-01-01 00:00:00');

    # TODO state-institutions should be split up into sigen-ca and sigov-ca
    add_carelation($self, 'state-institutions', 'Republika Slovenija', 'owned_by', '1970-01-01 00:00:00');

    return 0;
}

sub add_carelation {
    my ($self, $ca, $related_ca, $relation_type, $not_before) = @_;
    my $postfix = $self->tablepostfix;

    my $ca_actor = CertReader::DB::CAactor->new(db => $self->db, 'name' => $ca);
    $ca_actor->load(use_key => 'name');
    my $ca_actor_id = $ca_actor->id;

    my $related_ca_actor = CertReader::DB::CAactor->new(db => $self->db, 'name' => $related_ca);
    $related_ca_actor->load(use_key => 'name');
    my $related_ca_actor_id = $related_ca_actor->id;

    my $already_exists = 0;
    my $rel_iterator = CertReader::DB::CArelation::Manager->get_carelations_iterator_from_sql(
        db => $self->db,
        inject_results => 1,
        sql => "select * from ca_relation_$postfix where ca_id = $ca_actor_id and related_ca_id = $related_ca_actor_id",
    );
    while (my $rel = $rel_iterator->next) {
        if ($rel->type eq $relation_type and $rel->not_before eq $not_before) {
            $already_exists = 1;
        }
    }

    if (!$already_exists) {
        my $relation = CertReader::DB::CArelation->new('ca_id' => $ca_actor->id,
            'related_ca_id' => $related_ca_actor->id,
            'type' => $relation_type,
            'not_before' => $not_before
        );
        $relation->save;

    }

}

1;
