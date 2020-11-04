# Mozilla Root Store

See `mk-ca-bundle.pl`.

* [Mozilla's CA Certificate Program](https://wiki.mozilla.org/CA)
* [Mozilla Root Store Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/)
* [Intermediate CAs and revoked intermediates, and OneCRL](https://wiki.mozilla.org/CA/Intermediate_Certificates)

Mozilla manages its rootstore in the [Common CA Database](https://ccadb.org/). However, while the CCADB provides a [page with some interesting links](https://ccadb.org/resources), there seems to be no direct access to the stores maintained by mozilla, microsoft, and google.

## Revocations

* Mozilla maintains a list of *removed* CA certificates (**only includes removals since September 2014**) and **upcoming removals** [here](https://wiki.mozilla.org/CA/Removed_Certificates)
    * Includes the NSS and Firefox versions when the removal took effect (see column `Firefox Release When Removed`)
    * Includes a column with the `bugzilla` entry related to the removal
    * Includes a column with `Comments`
* Firefox revokes *intermediate* certificates via [OneCRL](https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/). See also link [above]((https://wiki.mozilla.org/CA/Intermediate_Certificates))
* [NSS:Release Versions](https://wiki.mozilla.org/NSS:Release_Versions) shows in which version of Mozilla products each root certificate was first available
