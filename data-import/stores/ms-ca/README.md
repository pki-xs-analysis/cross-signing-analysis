
# Microsoft Certificate Root Store

**WARNING: The excel sheets and the stl file do not match intuitively**, e.g., `Certplus Class 1 Primary CA (7D8CE822222B90C0B14342C7A8145D1F24351F4D1A1FE0EDFD312EE73FB00149)` is included in the `stl`-file but listed as `Disabled` in the Excel file `2019-03.xslx` and `notbefore 16.11.2016` in `2018-05-29`.
**TODO:** Check if the `stl` also contains the `Disabled` and `notbefore` requirements listed in the Excel files.

Look like we can also directly retrieve the currently trusted root database from [here](http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab). See also [at a walkthrough blogpost](http://unmitigatedrisk.com/?p=259).
After decompressing the cab-file, use ```openssl asn1parse -in authroot.stl -inform DER```.
Always the second HEX Dump after OID ```:1.3.6.1.4.1.311.10.11.11``` represents the sha1 of a certificate. DO NOT miss the first certificate, i.e., the very first Hex value preceded by ```:sha1```.

A history of `stl`-files is provided at [github](https://github.com/robstradling/authroot.stl.git).
**WARNING / TODO** Either notbefore or Disabled marks (cf. xlsx-files) are not available in the `stl` file or the scripts in the github repo do not parse them correctly. It's probably rather the latter. For example `Certplus Class 1 Primary CA (7D8CE822222B90C0B14342C7A8145D1F24351F4D1A1FE0EDFD312EE73FB00149)` (cf. above)

See also [Microsoft Root Updates](https://aka.ms/rootupdates). (Link provided in Excel lists)

## Excel lists

Microsoft operates a [Trusted Root Certificate Program](https://technet.microsoft.com/en-us/library/cc751157.aspx).
The [participants as of june-27-2017](https://social.technet.microsoft.com/wiki/contents/articles/38117.microsoft-trusted-root-certificate-program-participants-as-of-june-27-2017.aspx) of this program are available for [download](https://gallery.technet.microsoft.com/Trusted-Root-Certificate-123665ca).

There is also a [general overview](https://social.technet.microsoft.com/wiki/contents/articles/33315.microsoft-trusted-root-certificate-program-portal.aspx), the [requirements](https://social.technet.microsoft.com/wiki/contents/articles/31633.microsoft-trusted-root-program-requirements.aspx), and a listing of spreadsheets with the [Trusted Root Certificate Program Participants by date](http://social.technet.microsoft.com/wiki/contents/articles/31634.microsoft-trusted-root-certificate-program-participants.aspx).
The aforementioned list is not updated anymore. Use the following list: [Trusted Root Certificate Program Participants by date NEW](https://docs.microsoft.com/en-us/security/trusted-root/participants-list).

To convert the xlsx file: ```libreoffice --headless --convert-to csv 2017-06-27.xlsx``` (on OSX: ```/Applications/LibreOffice.app/Contents/MacOS/soffice --headless --convert-to csv 2017-06-27.xlsx```)

In addition, microsoft manages its rootstore in mozilla's [Common CA Database](https://ccadb.org/). However, while the CCADB provides a [page with some interesting links](https://ccadb.org/resources), there seems to be no direct access to the stores maintained by mozilla, microsoft, and google.


### NotBefore and Disables since 2017-09

The lists of 2017-09-26 include a new status column which may state Active, NotBefore, or Disabled
* The Microsoft NotBefore and Disabled status is **only available on Windows 10** operating systems.  All **other Windows operating systems will treat these Root Certificates as Active**. (see `2017-09-26.xlsx`)
* Active roots are trusted
* NotBefore status allow certificates issued prior to a specified date to continue to be trusted, while preventing certificates issued after that date from validating.
* Disabled roots have all EKU capabilities revoked while still allowing files that have been CodeSigned/TimeStamped prior to a specified date to continue to be trusted.
    * EKU = Enhanced Key Usage

Since Windows 10, some certificates in the lists are marked with `NotBefore` and `Disable` together with a date.

## Additional Links

* [Certificate Directory](https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/about-certificate-directory)
