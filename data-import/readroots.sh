#!/usr/bin/env bash

# Android
#    dates taken from git (date of last commit; NOT date of tag)
#    Android 7 and larger:  https://android.googlesource.com/platform/system/ca-certificates/+log/android-7.0.0_r35/files/
#    Android 6 and smaller: https://android.googlesource.com/platform/libcore/+log/android-6.0.0_r41/luni/src/main/files
# Android 2
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3_r1 --startdate 2010-10-26 --enddate 2010-10-26 stores/android/2.3_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.1_r1 --startdate 2010-10-26 --enddate 2010-10-26 stores/android/2.3.1_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.2_r1 --startdate 2010-10-26 --enddate 2010-10-26 stores/android/2.3.2_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.3_r1.1 --startdate 2010-10-26 --enddate 2011-03-03 stores/android/2.3.3_r1.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.4_r1 --startdate 2011-03-03 --enddate 2011-03-03 stores/android/2.3.4_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.5_r1 --startdate 2011-03-03 --enddate 2011-08-29 stores/android/2.3.5_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.6_r1 --startdate 2011-08-29 --enddate 2011-08-29 stores/android/2.3.6_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_2.3.7_r1 --startdate 2011-08-29 --enddate 2011-08-29 stores/android/2.3.7_r1/1.ca
# Android 4
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.0.1_r1.2 --startdate 2011-08-29 --enddate 2011-08-29 stores/android/4.0.1_r1.2/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.0.2_r1 --startdate 2011-08-29 --enddate 2011-08-29 stores/android/4.0.2_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.0.3_r1.1 --startdate 2011-08-29 --enddate 2011-08-29 stores/android/4.0.3_r1.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.0.4_r2.1 --startdate 2011-08-29 --enddate 2012-05-10 stores/android/4.0.4_r2.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.1.1_r6.1 --startdate 2012-05-10 --enddate 2012-05-10 stores/android/4.1.1_r6.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.1.2_r2.1 --startdate 2012-05-10 --enddate 2012-06-13 stores/android/4.1.2_r2.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.2.1_r1.2 --startdate 2012-06-13 --enddate 2012-06-13 stores/android/4.2.1_r1.2/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.2.2_r1.2b --startdate 2012-06-13 --enddate 2013-04-02 stores/android/4.2.2_r1.2b/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.3_r3.1 --startdate 2013-04-02 --enddate 2013-04-02 stores/android/4.3_r3.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.3.1_r1 --startdate 2013-04-02 --enddate 2013-08-16 stores/android/4.3.1_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.4_r1.2 --startdate 2013-08-16 --enddate 2013-08-16 stores/android/4.4_r1.2/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.4.1_r1 --startdate 2013-08-16 --enddate 2013-08-16 stores/android/4.4.1_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.4.2_r2 --startdate 2013-08-16 --enddate 2014-03-12 stores/android/4.4.2_r2/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.4.3_r1.1 --startdate 2014-03-12 --enddate 2014-03-12 stores/android/4.4.3_r1.1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_4.4.4_r2 --startdate 2014-03-12 --enddate 2014-09-26 stores/android/4.4.4_r2/1.ca
# Android 5
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_5.0.0_r6 --startdate 2014-09-26 --enddate 2014-09-26 stores/android/5.0.0_r6/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_5.0.1_r1 --startdate 2014-09-26 --enddate 2014-09-26 stores/android/5.0.1_r1/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_5.0.2_r3 --startdate 2014-09-26 --enddate 2014-12-05 stores/android/5.0.2_r3/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_5.1.1_r38 --startdate 2014-12-05 --enddate 2015-06-09 stores/android/5.1.1_r38/1.ca
# Android 6
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_6.0.0_r41 --startdate 2015-06-09 --enddate 2015-06-09 stores/android/6.0.0_r41/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_6.0.1_r81 --startdate 2015-06-09 --enddate 2016-03-21 stores/android/6.0.1_r81/1.ca
# Android 7
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_7.0.0_r35 --startdate 2016-03-21 --enddate 2016-08-29 stores/android/7.0.0_r35/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_7.1.0_r7 --startdate 2016-08-29 --enddate 2016-08-29 stores/android/7.1.0_r7/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_7.1.1_r58 --startdate 2016-08-29 --enddate 2016-08-29 stores/android/7.1.1_r58/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_7.1.2_r36 --startdate 2016-08-29 --enddate 2017-02-06 stores/android/7.1.2_r36/1.ca
# Android 8
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_8.0.0_r36 --startdate 2017-02-06 --enddate 2017-08-11 stores/android/8.0.0_r36/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_8.1.0_r41 --startdate 2017-08-11 --enddate 2017-08-11 stores/android/8.1.0_r41/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_8.1.0_r43 --startdate 2017-08-11 --enddate 2017-12-01 stores/android/8.1.0_r43/1.ca
# Android 9
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r16 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r16/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r19 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r19/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r3 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r3/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r30 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r30/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r31 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r31/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r34 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r34/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r35 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r35/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r36 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r36/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r40 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r40/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r43 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r43/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r5 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r5/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_9.0.0_r9 --startdate 2017-12-01 --enddate 2017-12-01 stores/android/9.0.0_r9/1.ca
# Android 10
# tag android-q-preview-5
mx-run -Ilib CertReader::App::ImportStore --rootstore android --tag android_10.0.0_r000_q-preview-5 --startdate 2017-12-01 stores/android/10.0.0_r000_q-preview-5/1.ca  # TODO enddate

# iOS
# iOS 5
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios5_20180721 --startdate 2018-07-21 stores/ios/ios5/2018-07-21.ca  # TODO enddate
# iOS 6
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios6_20180721 --startdate 2018-07-21 stores/ios/ios6/2018-07-21.ca  # TODO enddate
# iOS 7
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios7_20140529 --startdate 2014-05-29 --enddate 2017-02-24 stores/ios/ios7/2014-05-29.ca # Johanna's
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios7_20170224 --startdate 2017-02-24 stores/ios/ios7/2017-02-24.ca  # TODO enddate
# iOS8  TODO
# iOS9  TODO
# iOS 10
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios10_20190505 --startdate 2019-05-05 --enddate 2019-05-25 stores/ios/ios10/2019-05-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios10_20190525 --startdate 2019-05-25 --enddate 2019-07-29 stores/ios/ios10/2019-05-25.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios10_20190729 --startdate 2019-07-29 stores/ios/ios10/2019-07-29.ca  # TODO enddate
# iOS 11
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20180116 --startdate 2018-01-16 --enddate 2018-07-05 stores/ios/ios11/2018-01-16.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20180705 --startdate 2018-07-05 --enddate 2019-03-26 stores/ios/ios11/2018-07-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20190326 --startdate 2019-03-26 --enddate 2019-04-09 stores/ios/ios11/2019-03-26.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20190409 --startdate 2019-04-09 --enddate 2019-04-11 stores/ios/ios11/2019-04-09.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20190411 --startdate 2019-04-11 --enddate 2019-05-05 stores/ios/ios11/2019-04-11.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20190505 --startdate 2019-05-05 --enddate 2019-07-29 stores/ios/ios11/2019-05-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios11_20190729 --startdate 2019-07-29 stores/ios/ios11/2019-07-29.ca  # TODO enddate
# iOS 12
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios12_20190409 --startdate 2019-04-09 --enddate 2019-05-05 stores/ios/ios12/2019-04-09.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios12_20190505 --startdate 2019-05-05 --enddate 2019-05-12 stores/ios/ios12/2019-05-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios12_20190512 --startdate 2019-05-12 --enddate 2019-07-29 stores/ios/ios12/2019-05-12.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore iOS --tag ios12_20190729 --startdate 2019-07-29 stores/ios/ios12/2019-07-29.ca  # TODO enddate

# Mozilla / Firefox
# dates extracted from https://hg.mozilla.org/releases/mozilla-release/tags
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF3_1a1 --startdate 2008-07-25 --enddate 2008-08-29 stores/mozilla/FIREFOX_3_1a1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF3_1a2 --startdate 2008-08-29 --enddate 2011-04-14 stores/mozilla/FIREFOX_3_1a2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF4_0_1 --startdate 2011-04-14 --enddate 2011-06-15 stores/mozilla/FIREFOX_4_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF5_0 --startdate  2011-06-15 --enddate 2011-07-08 stores/mozilla/FIREFOX_5_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF5_0_1 --startdate 2011-07-08 --enddate 2011-08-11 stores/mozilla/FIREFOX_5_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF6_0 --startdate 2011-08-11 --enddate 2011-08-30 stores/mozilla/FIREFOX_6_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF6_0_1 --startdate 2011-08-30 --enddate 2011-09-02 stores/mozilla/FIREFOX_6_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF6_0_2 --startdate 2011-09-02 --enddate 2011-09-23 stores/mozilla/FIREFOX_6_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF7_0 --startdate 2011-09-23 --enddate 2011-09-29 stores/mozilla/FIREFOX_7_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF7_0_1 --startdate 2011-09-29 --enddate 2011-11-05 stores/mozilla/FIREFOX_7_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF8_0 --startdate 2011-11-05 --enddate 2011-11-19 stores/mozilla/FIREFOX_8_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF8_0_1 --startdate 2011-11-19 --enddate 2011-12-16 stores/mozilla/FIREFOX_8_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF9_0 --startdate 2011-12-16 --enddate 2011-12-21 stores/mozilla/FIREFOX_9_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF9_0_1 --startdate 2011-12-21 --enddate 2012-01-29 stores/mozilla/FIREFOX_9_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF10_0 --startdate 2012-01-29 --enddate 2012-02-08 stores/mozilla/FIREFOX_10_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF10_0_1 --startdate 2012-02-08 --enddate 2012-02-16 stores/mozilla/FIREFOX_10_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF10_0_2 --startdate 2012-02-16 --enddate 2012-03-13 stores/mozilla/FIREFOX_10_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF11_0 --startdate 2012-03-13 --enddate 2012-04-20 stores/mozilla/FIREFOX_11_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF12_0 --startdate 2012-04-20 --enddate 2012-06-01 stores/mozilla/FIREFOX_12_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF13_0 --startdate 2012-06-01 --enddate 2012-06-14 stores/mozilla/FIREFOX_13_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF13_0_1 --startdate 2012-06-14 --enddate 2012-06-23 stores/mozilla/FIREFOX_13_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF13_0_2 --startdate 2012-06-23 --enddate 2012-07-13 stores/mozilla/FIREFOX_13_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF14_0_1 --startdate 2012-07-13 --enddate 2012-08-25 stores/mozilla/FIREFOX_14_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF15_0 --startdate 2012-08-25 --enddate 2012-09-05 stores/mozilla/FIREFOX_15_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF15_0_1 --startdate 2012-09-05 --enddate 2012-10-06 stores/mozilla/FIREFOX_15_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF16_0 --startdate 2012-10-06 --enddate 2012-10-10 stores/mozilla/FIREFOX_16_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF16_0_1 --startdate 2012-10-10 --enddate 2012-10-24 stores/mozilla/FIREFOX_16_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF16_0_2 --startdate 2012-10-24 --enddate 2012-11-20 stores/mozilla/FIREFOX_16_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF17_0 --startdate 2012-11-20 --enddate 2012-11-29 stores/mozilla/FIREFOX_17_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF17_0_1 --startdate 2012-11-29 --enddate 2013-01-04 stores/mozilla/FIREFOX_17_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF18_0 --startdate 2013-01-04 --enddate 2013-01-16 stores/mozilla/FIREFOX_18_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF18_0_1 --startdate 2013-01-16 --enddate 2013-02-01 stores/mozilla/FIREFOX_18_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF18_0_2 --startdate 2013-02-01 --enddate 2013-02-15 stores/mozilla/FIREFOX_18_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF19_0 --startdate 2013-02-15 --enddate 2013-02-27 stores/mozilla/FIREFOX_19_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF19_0_1 --startdate 2013-02-27 --enddate 2013-03-07 stores/mozilla/FIREFOX_19_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF19_0_2 --startdate 2013-03-07 --enddate 2013-03-26 stores/mozilla/FIREFOX_19_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF20_0 --startdate 2013-03-26 --enddate 2013-04-10 stores/mozilla/FIREFOX_20_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF20_0_1 --startdate 2013-04-10 --enddate 2013-05-11 stores/mozilla/FIREFOX_20_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF21_0 --startdate 2013-05-11 --enddate 2013-06-19 stores/mozilla/FIREFOX_21_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF22_0 --startdate 2013-06-19 --enddate 2013-08-02 stores/mozilla/FIREFOX_22_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF23_0 --startdate 2013-08-02 --enddate 2013-08-16 stores/mozilla/FIREFOX_23_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF23_0_1 --startdate 2013-08-16 --enddate 2013-09-11 stores/mozilla/FIREFOX_23_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF24_0 --startdate 2013-09-11 --enddate 2013-10-25 stores/mozilla/FIREFOX_24_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF25_0 --startdate 2013-10-25 --enddate 2013-11-13 stores/mozilla/FIREFOX_25_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF25_0_1 --startdate 2013-11-13 --enddate 2013-12-05 stores/mozilla/FIREFOX_25_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF26_0 --startdate 2013-12-05 --enddate 2014-01-28 stores/mozilla/FIREFOX_26_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF27_0 --startdate 2014-01-28 --enddate 2014-02-12 stores/mozilla/FIREFOX_27_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF27_0_1 --startdate 2014-02-12 --enddate 2014-03-15 stores/mozilla/FIREFOX_27_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF28_0 --startdate 2014-03-15 --enddate 2014-04-22 stores/mozilla/FIREFOX_28_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF29_0 --startdate 2014-04-22 --enddate 2014-05-06 stores/mozilla/FIREFOX_29_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF29_0_1 --startdate 2014-05-06 --enddate 2014-06-06 stores/mozilla/FIREFOX_29_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF30_0 --startdate 2014-06-06 --enddate 2014-07-17 stores/mozilla/FIREFOX_30_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF31_0 --startdate 2014-07-17 --enddate 2014-08-26 stores/mozilla/FIREFOX_31_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF32_0 --startdate 2014-08-26 --enddate 2014-09-11 stores/mozilla/FIREFOX_32_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF32_0_1 --startdate 2014-09-11 --enddate 2014-09-18 stores/mozilla/FIREFOX_32_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF32_0_2 --startdate 2014-09-18 --enddate 2014-09-24 stores/mozilla/FIREFOX_32_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF32_0_3 --startdate 2014-09-24 --enddate 2014-10-11 stores/mozilla/FIREFOX_32_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF33_0 --startdate 2014-10-11 --enddate 2014-10-23 stores/mozilla/FIREFOX_33_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF33_0_1 --startdate 2014-10-23 --enddate 2014-10-27 stores/mozilla/FIREFOX_33_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF33_0_2 --startdate 2014-10-27 --enddate 2014-11-05 stores/mozilla/FIREFOX_33_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF33_0_3 --startdate 2014-11-05 --enddate 2014-11-06 stores/mozilla/FIREFOX_33_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF33_1 --startdate 2014-11-06 --enddate 2014-11-13 stores/mozilla/FIREFOX_33_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF33_1_1 --startdate 2014-11-13 --enddate 2014-11-26 stores/mozilla/FIREFOX_33_1_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF34_0 --startdate 2014-11-26 --enddate 2014-11-26 stores/mozilla/FIREFOX_34_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF34_0_5 --startdate 2014-11-26 --enddate 2015-01-09 stores/mozilla/FIREFOX_34_0_5_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF35_0 --startdate 2015-01-09 --enddate 2015-01-23 stores/mozilla/FIREFOX_35_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF35_0_1 --startdate 2015-01-23 --enddate 2015-02-23 stores/mozilla/FIREFOX_35_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF36_0 --startdate 2015-02-23 --enddate 2015-03-05 stores/mozilla/FIREFOX_36_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF36_0_1 --startdate 2015-03-05 --enddate 2015-03-20 stores/mozilla/FIREFOX_36_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF36_0_3 --startdate 2015-03-20 --enddate 2015-03-21 stores/mozilla/FIREFOX_36_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF36_0_4 --startdate 2015-03-21 --enddate 2015-03-27 stores/mozilla/FIREFOX_36_0_4_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF37_0 --startdate 2015-03-27 --enddate 2015-04-03 stores/mozilla/FIREFOX_37_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF37_0_1 --startdate 2015-04-03 --enddate 2015-04-15 stores/mozilla/FIREFOX_37_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF37_0_2 --startdate 2015-04-15 --enddate 2015-05-07 stores/mozilla/FIREFOX_37_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0 --startdate 2015-05-07 --enddate 2015-05-14 stores/mozilla/FIREFOX_38_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0_1 --startdate 2015-05-14 --enddate 2015-05-25 stores/mozilla/FIREFOX_38_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0_5 --startdate 2015-05-25 --enddate 2015-05-11 stores/mozilla/FIREFOX_38_0_5_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0_5b1 --startdate 2015-05-11 --enddate 2015-05-15 stores/mozilla/FIREFOX_38_0_5b1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0_5b2 --startdate 2015-05-15 --enddate 2015-05-18 stores/mozilla/FIREFOX_38_0_5b2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0_5b3 --startdate 2015-05-18 --enddate 2015-06-05 stores/mozilla/FIREFOX_38_0_5b3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF38_0_6 --startdate 2015-06-05 --enddate 2015-07-01 stores/mozilla/FIREFOX_38_0_6_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF39_0 --startdate 2015-07-01 --enddate 2015-08-06 stores/mozilla/FIREFOX_39_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF39_0_3 --startdate 2015-08-06 --enddate 2015-08-07 stores/mozilla/FIREFOX_39_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF40_0 --startdate 2015-08-07 --enddate 2015-08-12 stores/mozilla/FIREFOX_40_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF40_0_1 --startdate 2015-08-12 --enddate 2015-08-13 stores/mozilla/FIREFOX_40_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF40_0_2 --startdate 2015-08-13 --enddate 2015-08-26 stores/mozilla/FIREFOX_40_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF40_0_3 --startdate 2015-08-26 --enddate 2015-09-18 stores/mozilla/FIREFOX_40_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF41_0 --startdate 2015-09-18 --enddate 2015-09-29 stores/mozilla/FIREFOX_41_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF41_0_1 --startdate 2015-09-29 --enddate 2015-10-14 stores/mozilla/FIREFOX_41_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF41_0_2 --startdate 2015-10-14 --enddate 2015-10-29 stores/mozilla/FIREFOX_41_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF42_0 --startdate 2015-10-29 --enddate 2015-12-08 stores/mozilla/FIREFOX_42_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF43_0 --startdate 2015-12-08 --enddate 2015-12-17 stores/mozilla/FIREFOX_43_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF43_0_1 --startdate 2015-12-17 --enddate 2015-12-21 stores/mozilla/FIREFOX_43_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF43_0_2 --startdate 2015-12-21 --enddate 2015-12-23 stores/mozilla/FIREFOX_43_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF43_0_3 --startdate 2015-12-23 --enddate 2016-01-06 stores/mozilla/FIREFOX_43_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF43_0_4 --startdate 2016-01-06 --enddate 2016-01-24 stores/mozilla/FIREFOX_43_0_4_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF44_0 --startdate 2016-01-24 --enddate 2016-02-06 stores/mozilla/FIREFOX_44_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF44_0_1 --startdate 2016-02-06 --enddate 2016-02-11 stores/mozilla/FIREFOX_44_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF44_0_2 --startdate 2016-02-11 --enddate 2016-03-03 stores/mozilla/FIREFOX_44_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF45_0 --startdate 2016-03-03 --enddate 2016-03-15 stores/mozilla/FIREFOX_45_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF45_0_1 --startdate 2016-03-15 --enddate 2016-04-08 stores/mozilla/FIREFOX_45_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF45_0_2 --startdate 2016-04-08 --enddate 2016-04-21 stores/mozilla/FIREFOX_45_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF46_0 --startdate 2016-04-21 --enddate 2016-05-03 stores/mozilla/FIREFOX_46_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF46_0_1 --startdate 2016-05-03 --enddate 2016-06-04 stores/mozilla/FIREFOX_46_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF47_0 --startdate 2016-06-04 --enddate 2016-06-02 stores/mozilla/FIREFOX_47_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF47_0_1 --startdate 2016-06-02 --enddate 2016-05-31 stores/mozilla/FIREFOX_47_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF47_0_2 --startdate 2016-05-31 --enddate 2016-06-30 stores/mozilla/FIREFOX_47_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF48_0 --startdate 2016-06-30 --enddate 2016-08-17 stores/mozilla/FIREFOX_48_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF48_0_1 --startdate 2016-08-17 --enddate 2016-08-22 stores/mozilla/FIREFOX_48_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF48_0_2 --startdate 2016-08-22 --enddate 2016-09-16 stores/mozilla/FIREFOX_48_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF49_0 --startdate 2016-09-16 --enddate 2016-08-22 stores/mozilla/FIREFOX_49_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF49_0_1 --startdate 2016-08-22 --enddate 2016-06-29 stores/mozilla/FIREFOX_49_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF49_0_2 --startdate 2016-06-29 --enddate 2016-11-05 stores/mozilla/FIREFOX_49_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF50_0 --startdate 2016-11-05 --enddate 2016-11-23 stores/mozilla/FIREFOX_50_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF50_0_1 --startdate 2016-11-23 --enddate 2016-11-30 stores/mozilla/FIREFOX_50_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF50_0_2 --startdate 2016-11-30 --enddate 2016-11-23 stores/mozilla/FIREFOX_50_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF50_1_0 --startdate 2016-11-23 --enddate 2017-01-18 stores/mozilla/FIREFOX_50_1_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF51_0 --startdate 2017-01-18 --enddate 2016-08-22 stores/mozilla/FIREFOX_51_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF51_0_1 --startdate 2016-08-22 --enddate 2017-03-02 stores/mozilla/FIREFOX_51_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF52_0 --startdate 2017-03-02 --enddate 2017-03-02 stores/mozilla/FIREFOX_52_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF52_0_1 --startdate 2017-03-02 --enddate 2017-03-15 stores/mozilla/FIREFOX_52_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF52_0_2 --startdate 2017-03-15 --enddate 2017-04-13 stores/mozilla/FIREFOX_52_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF53_0 --startdate 2017-04-13 --enddate 2017-05-03 stores/mozilla/FIREFOX_53_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF53_0_2 --startdate 2017-05-03 --enddate 2017-05-04 stores/mozilla/FIREFOX_53_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF53_0_3 --startdate 2017-05-04 --enddate 2017-06-08 stores/mozilla/FIREFOX_53_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF54_0 --startdate 2017-06-08 --enddate 2017-06-28 stores/mozilla/FIREFOX_54_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF54_0_1 --startdate 2017-06-28 --enddate 2017-08-03 stores/mozilla/FIREFOX_54_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF55_0 --startdate 2017-08-03 --enddate 2017-08-09 stores/mozilla/FIREFOX_55_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF55_0_1 --startdate 2017-08-09 --enddate 2017-08-11 stores/mozilla/FIREFOX_55_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF55_0_2 --startdate 2017-08-11 --enddate 2017-08-23 stores/mozilla/FIREFOX_55_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF55_0_3 --startdate 2017-08-23 --enddate 2017-09-26 stores/mozilla/FIREFOX_55_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF56_0 --startdate 2017-09-26 --enddate 2017-09-28 stores/mozilla/FIREFOX_56_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF56_0_1 --startdate 2017-09-28 --enddate 2017-10-16 stores/mozilla/FIREFOX_56_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF56_0_2 --startdate 2017-10-16 --enddate 2017-11-12 stores/mozilla/FIREFOX_56_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF57_0 --startdate 2017-11-12 --enddate 2017-11-27 stores/mozilla/FIREFOX_57_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF57_0_1 --startdate 2017-11-27 --enddate 2017-12-06 stores/mozilla/FIREFOX_57_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF57_0_2 --startdate 2017-12-06 --enddate 2017-12-21 stores/mozilla/FIREFOX_57_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF57_0_3 --startdate 2017-12-21 --enddate 2017-12-30 stores/mozilla/FIREFOX_57_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF57_0_4 --startdate 2017-12-30 --enddate 2018-01-18 stores/mozilla/FIREFOX_57_0_4_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF58_0 --startdate 2018-01-18 --enddate 2018-01-24 stores/mozilla/FIREFOX_58_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF58_0_1 --startdate 2018-01-24 --enddate 2018-01-18 stores/mozilla/FIREFOX_58_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF58_0_2 --startdate 2018-01-18 --enddate 2018-03-10 stores/mozilla/FIREFOX_58_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF59_0 --startdate 2018-03-10 --enddate 2018-03-15 stores/mozilla/FIREFOX_59_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF59_0_1 --startdate 2018-03-15 --enddate 2018-03-22 stores/mozilla/FIREFOX_59_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF59_0_2 --startdate 2018-03-22 --enddate 2018-04-09 stores/mozilla/FIREFOX_59_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF59_0_3 --startdate 2018-04-09 --enddate 2018-04-23 stores/mozilla/FIREFOX_59_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF60_0 --startdate 2018-04-23 --enddate 2018-05-16 stores/mozilla/FIREFOX_60_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF60_0_1 --startdate 2018-05-16 --enddate 2018-05-25 stores/mozilla/FIREFOX_60_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF60_0_2 --startdate 2018-05-25 --enddate 2018-06-21 stores/mozilla/FIREFOX_60_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF61_0 --startdate 2018-06-21 --enddate 2018-07-02 stores/mozilla/FIREFOX_61_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF61_0_1 --startdate 2018-07-02 --enddate 2018-08-07 stores/mozilla/FIREFOX_61_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF61_0_2 --startdate 2018-08-07 --enddate 2018-08-29 stores/mozilla/FIREFOX_61_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF62_0 --startdate  2018-08-29 --enddate 2018-09-18 stores/mozilla/FIREFOX_62_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF62_0_2 --startdate 2018-09-18 --enddate 2018-10-01 stores/mozilla/FIREFOX_62_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF62_0_3 --startdate 2018-10-01 --enddate 2018-10-17 stores/mozilla/FIREFOX_62_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF63_0 --startdate 2018-10-17 --enddate 2018-10-29 stores/mozilla/FIREFOX_63_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF63_0_1 --startdate 2018-10-29 --enddate 2018-11-14 stores/mozilla/FIREFOX_63_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF63_0_3 --startdate 2018-11-14 --enddate 2018-12-06 stores/mozilla/FIREFOX_63_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF64_0 --startdate 2018-12-06 --enddate 2018-12-20 stores/mozilla/FIREFOX_64_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF64_0_2 --startdate 2018-12-20 --enddate 2019-01-22 stores/mozilla/FIREFOX_64_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF65_0 --startdate 2019-01-22 --enddate 2019-02-11 stores/mozilla/FIREFOX_65_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF65_0_1 --startdate 2019-02-11 --enddate 2019-02-25 stores/mozilla/FIREFOX_65_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF65_0_2 --startdate 2019-02-25 --enddate 2019-03-14 stores/mozilla/FIREFOX_65_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF66_0 --startdate 2019-03-14 --enddate 2019-03-21 stores/mozilla/FIREFOX_66_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF66_0_1 --startdate 2019-03-21 --enddate 2019-03-21 stores/mozilla/FIREFOX_66_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF66_0_2 --startdate 2019-03-21 --enddate 2019-04-05 stores/mozilla/FIREFOX_66_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF66_0_3 --startdate 2019-04-05 --enddate 2019-05-04 stores/mozilla/FIREFOX_66_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF66_0_4 --startdate 2019-05-04 --enddate 2019-05-07 stores/mozilla/FIREFOX_66_0_4_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF66_0_5 --startdate 2019-05-07 --enddate 2019-05-17 stores/mozilla/FIREFOX_66_0_5_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF67_0 --startdate 2019-05-17 --enddate 2019-05-23 stores/mozilla/FIREFOX_67_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF67_0_1 --startdate 2019-05-23 --enddate 2019-06-06 stores/mozilla/FIREFOX_67_0_1_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF67_0_2 --startdate 2019-06-06 --enddate 2019-06-18 stores/mozilla/FIREFOX_67_0_2_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF67_0_3 --startdate 2019-06-18 --enddate 2019-06-19 stores/mozilla/FIREFOX_67_0_3_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF67_0_4 --startdate 2019-06-19 --enddate 2019-07-05 stores/mozilla/FIREFOX_67_0_4_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF68_0 --startdate 2019-07-05 --enddate 2019-07-17 stores/mozilla/FIREFOX_68_0_RELEASE/ca-bundle.crt
mx-run -Ilib CertReader::App::ImportStore --rootstore mozilla --tag FF68_0_1 --startdate 2019-07-17 --enddate 2019-07-30 stores/mozilla/FIREFOX_68_0_1_RELEASE/ca-bundle.crt

# Microsoft
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20121216 --startdate 2012-12-16 --enddate 2016-11-17 stores/ms-ca/2012-12-16/1.ca    # Johanna's
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20161117 --startdate 2016-11-17 --enddate 2017-04-25 stores/ms-ca/2016-11-17/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20170425 --startdate 2017-04-25 --enddate 2017-06-27 stores/ms-ca/2017-04-25/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20170627 --startdate 2017-06-27 --enddate 2017-09-26 stores/ms-ca/2017-06-27/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20170926 --startdate 2017-09-26 --enddate 2017-11-28 stores/ms-ca/2017-09-26/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20171128 --startdate 2017-11-28 --enddate 2018-01-30 stores/ms-ca/2017-11-28/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180130 --startdate 2018-01-30 --enddate 2018-03-29 stores/ms-ca/2018-01-30/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180329 --startdate 2018-03-29 --enddate 2018-04-25 stores/ms-ca/2018-03-29/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180425 --startdate 2018-04-25 --enddate 2018-05-29 stores/ms-ca/2018-04-25/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180529 --startdate 2018-05-29 --enddate 2018-06-26 stores/ms-ca/2018-05-29/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180626 --startdate 2018-06-26 --enddate 2018-07-31 stores/ms-ca/2018-06-26/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180731 --startdate 2018-07-31 --enddate 2018-08-28 stores/ms-ca/2018-07-31/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20180828 --startdate 2018-08-28 --enddate 2018-10-02 stores/ms-ca/2018-08-28/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20181002 --startdate 2018-10-02 --enddate 2018-10-30 stores/ms-ca/2018-10-02/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-20181030 --startdate 2018-10-30 --enddate 2019-02-01 stores/ms-ca/2018-10-30/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-201902 --startdate 2019-02-01 --enddate 2019-03-01 stores/ms-ca/2019-02/1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore microsoft --tag ms-201903 --startdate 2019-03-01 --enddate 2019-07-01 stores/ms-ca/2019-03/1.ca

# OSX
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx-10.9_20140529 --startdate 2014-05-29 --enddate 2018-01-16 stores/osx/osx-10.9/2014-05-29.ca # Johanna's
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.12_20180116 --startdate 2018-01-16 --enddate 2019-04-09 stores/osx/osx-10.12/2018-01-16.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.12_20190409 --startdate 2019-04-09 --enddate 2019-05-05 stores/osx/osx-10.12/2019-04-09.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.12_20190505 --startdate 2019-05-05 --enddate 2019-06-17 stores/osx/osx-10.12/2019-05-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.12_20190617 --startdate 2019-06-17 --enddate 2019-07-29 stores/osx/osx-10.12/2019-06-17.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.12_20190729 --startdate 2019-07-29 --enddate 2018-01-16 stores/osx/osx-10.12/2019-07-29.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.13_20180116 --startdate 2018-01-16 --enddate 2018-07-05 stores/osx/osx-10.13/2018-01-16.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.13_20180705 --startdate 2018-07-05 --enddate 2019-04-09 stores/osx/osx-10.13/2018-07-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.13_20190409 --startdate 2019-04-09 --enddate 2019-05-05 stores/osx/osx-10.13/2019-04-09.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.13_20190505 --startdate 2019-05-05 --enddate 2019-07-29 stores/osx/osx-10.13/2019-05-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.13_20190729 --startdate 2019-07-29 --enddate 2019-04-09 stores/osx/osx-10.13/2019-07-29.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.14_20190409 --startdate 2019-04-09 --enddate 2019-05-05 stores/osx/osx-10.14/2019-04-09.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.14_20190505 --startdate 2019-05-05 --enddate 2019-05-12 stores/osx/osx-10.14/2019-05-05.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.14_20190512 --startdate 2019-05-12 --enddate 2019-07-29 stores/osx/osx-10.14/2019-05-12.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore OSX --tag osx10.14_20190729 --startdate 2019-07-29 stores/osx/osx-10.14/2019-07-29.ca  # TODO enddate (last checked for updates: 2020-08-09)


# Grid rootstores
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.1 stores/grid/igtf-preinstalled-bundle-classic-1.1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.10 stores/grid/igtf-preinstalled-bundle-classic-1.10.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.101 stores/grid/igtf-preinstalled-bundle-classic-1.101.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.11 stores/grid/igtf-preinstalled-bundle-classic-1.11.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.12 stores/grid/igtf-preinstalled-bundle-classic-1.12.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.13 stores/grid/igtf-preinstalled-bundle-classic-1.13.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.14 stores/grid/igtf-preinstalled-bundle-classic-1.14.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.15 stores/grid/igtf-preinstalled-bundle-classic-1.15.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.16 stores/grid/igtf-preinstalled-bundle-classic-1.16.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.17 stores/grid/igtf-preinstalled-bundle-classic-1.17.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.18 stores/grid/igtf-preinstalled-bundle-classic-1.18.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.19 stores/grid/igtf-preinstalled-bundle-classic-1.19.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.2 stores/grid/igtf-preinstalled-bundle-classic-1.2.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.20 stores/grid/igtf-preinstalled-bundle-classic-1.20.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.21 stores/grid/igtf-preinstalled-bundle-classic-1.21.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.22 stores/grid/igtf-preinstalled-bundle-classic-1.22.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.24 stores/grid/igtf-preinstalled-bundle-classic-1.24.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.25 stores/grid/igtf-preinstalled-bundle-classic-1.25.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.26 stores/grid/igtf-preinstalled-bundle-classic-1.26.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.27 stores/grid/igtf-preinstalled-bundle-classic-1.27.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.28 stores/grid/igtf-preinstalled-bundle-classic-1.28.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.29 stores/grid/igtf-preinstalled-bundle-classic-1.29.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.30 stores/grid/igtf-preinstalled-bundle-classic-1.30.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.31 stores/grid/igtf-preinstalled-bundle-classic-1.31.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.32 stores/grid/igtf-preinstalled-bundle-classic-1.32.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.33 stores/grid/igtf-preinstalled-bundle-classic-1.33.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.34 stores/grid/igtf-preinstalled-bundle-classic-1.34.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.35 stores/grid/igtf-preinstalled-bundle-classic-1.35.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.36 stores/grid/igtf-preinstalled-bundle-classic-1.36.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.37 stores/grid/igtf-preinstalled-bundle-classic-1.37.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.38 stores/grid/igtf-preinstalled-bundle-classic-1.38.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.39 stores/grid/igtf-preinstalled-bundle-classic-1.39.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.4 stores/grid/igtf-preinstalled-bundle-classic-1.4.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.40 stores/grid/igtf-preinstalled-bundle-classic-1.40.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.41 stores/grid/igtf-preinstalled-bundle-classic-1.41.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.42 stores/grid/igtf-preinstalled-bundle-classic-1.42.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.43 stores/grid/igtf-preinstalled-bundle-classic-1.43.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.44 stores/grid/igtf-preinstalled-bundle-classic-1.44.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.45 stores/grid/igtf-preinstalled-bundle-classic-1.45.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.46 stores/grid/igtf-preinstalled-bundle-classic-1.46.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.47 stores/grid/igtf-preinstalled-bundle-classic-1.47.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.48 stores/grid/igtf-preinstalled-bundle-classic-1.48.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.49 stores/grid/igtf-preinstalled-bundle-classic-1.49.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.5 stores/grid/igtf-preinstalled-bundle-classic-1.5.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.50 stores/grid/igtf-preinstalled-bundle-classic-1.50.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.51 stores/grid/igtf-preinstalled-bundle-classic-1.51.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.52 stores/grid/igtf-preinstalled-bundle-classic-1.52.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.53 stores/grid/igtf-preinstalled-bundle-classic-1.53.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.54 stores/grid/igtf-preinstalled-bundle-classic-1.54.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.55 stores/grid/igtf-preinstalled-bundle-classic-1.55.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.56 stores/grid/igtf-preinstalled-bundle-classic-1.56.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.57 stores/grid/igtf-preinstalled-bundle-classic-1.57.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.58 stores/grid/igtf-preinstalled-bundle-classic-1.58.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.59 stores/grid/igtf-preinstalled-bundle-classic-1.59.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.6 stores/grid/igtf-preinstalled-bundle-classic-1.6.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.60 stores/grid/igtf-preinstalled-bundle-classic-1.60.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.61 stores/grid/igtf-preinstalled-bundle-classic-1.61.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.62 stores/grid/igtf-preinstalled-bundle-classic-1.62.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.63 stores/grid/igtf-preinstalled-bundle-classic-1.63.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.64 stores/grid/igtf-preinstalled-bundle-classic-1.64.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.65 stores/grid/igtf-preinstalled-bundle-classic-1.65.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.67 stores/grid/igtf-preinstalled-bundle-classic-1.67.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.68 stores/grid/igtf-preinstalled-bundle-classic-1.68.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.69 stores/grid/igtf-preinstalled-bundle-classic-1.69.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.7 stores/grid/igtf-preinstalled-bundle-classic-1.7.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.70 stores/grid/igtf-preinstalled-bundle-classic-1.70.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.71 stores/grid/igtf-preinstalled-bundle-classic-1.71.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.72 stores/grid/igtf-preinstalled-bundle-classic-1.72.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.73 stores/grid/igtf-preinstalled-bundle-classic-1.73.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.74 stores/grid/igtf-preinstalled-bundle-classic-1.74.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.75 stores/grid/igtf-preinstalled-bundle-classic-1.75.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.76 stores/grid/igtf-preinstalled-bundle-classic-1.76.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.77 stores/grid/igtf-preinstalled-bundle-classic-1.77.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.78 stores/grid/igtf-preinstalled-bundle-classic-1.78.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.79 stores/grid/igtf-preinstalled-bundle-classic-1.79.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.8 stores/grid/igtf-preinstalled-bundle-classic-1.8.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.80 stores/grid/igtf-preinstalled-bundle-classic-1.80.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.81 stores/grid/igtf-preinstalled-bundle-classic-1.81.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.82 stores/grid/igtf-preinstalled-bundle-classic-1.82.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.83 stores/grid/igtf-preinstalled-bundle-classic-1.83.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.84 stores/grid/igtf-preinstalled-bundle-classic-1.84.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.85 stores/grid/igtf-preinstalled-bundle-classic-1.85.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.86 stores/grid/igtf-preinstalled-bundle-classic-1.86.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.87 stores/grid/igtf-preinstalled-bundle-classic-1.87.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.88 stores/grid/igtf-preinstalled-bundle-classic-1.88.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.89 stores/grid/igtf-preinstalled-bundle-classic-1.89.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.9 stores/grid/igtf-preinstalled-bundle-classic-1.9.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.90 stores/grid/igtf-preinstalled-bundle-classic-1.90.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.91 stores/grid/igtf-preinstalled-bundle-classic-1.91.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.92 stores/grid/igtf-preinstalled-bundle-classic-1.92.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.93 stores/grid/igtf-preinstalled-bundle-classic-1.93.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.94 stores/grid/igtf-preinstalled-bundle-classic-1.94.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.95 stores/grid/igtf-preinstalled-bundle-classic-1.95.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.96 stores/grid/igtf-preinstalled-bundle-classic-1.96.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.97 stores/grid/igtf-preinstalled-bundle-classic-1.97.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.98 stores/grid/igtf-preinstalled-bundle-classic-1.98.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-classic-1.99 stores/grid/igtf-preinstalled-bundle-classic-1.99.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.101 stores/grid/igtf-preinstalled-bundle-iota-1.101.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.56 stores/grid/igtf-preinstalled-bundle-iota-1.56.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.57 stores/grid/igtf-preinstalled-bundle-iota-1.57.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.58 stores/grid/igtf-preinstalled-bundle-iota-1.58.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.59 stores/grid/igtf-preinstalled-bundle-iota-1.59.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.60 stores/grid/igtf-preinstalled-bundle-iota-1.60.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.61 stores/grid/igtf-preinstalled-bundle-iota-1.61.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.62 stores/grid/igtf-preinstalled-bundle-iota-1.62.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.63 stores/grid/igtf-preinstalled-bundle-iota-1.63.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.64 stores/grid/igtf-preinstalled-bundle-iota-1.64.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.65 stores/grid/igtf-preinstalled-bundle-iota-1.65.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.67 stores/grid/igtf-preinstalled-bundle-iota-1.67.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.68 stores/grid/igtf-preinstalled-bundle-iota-1.68.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.69 stores/grid/igtf-preinstalled-bundle-iota-1.69.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.70 stores/grid/igtf-preinstalled-bundle-iota-1.70.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.71 stores/grid/igtf-preinstalled-bundle-iota-1.71.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.72 stores/grid/igtf-preinstalled-bundle-iota-1.72.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.73 stores/grid/igtf-preinstalled-bundle-iota-1.73.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.74 stores/grid/igtf-preinstalled-bundle-iota-1.74.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.75 stores/grid/igtf-preinstalled-bundle-iota-1.75.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.76 stores/grid/igtf-preinstalled-bundle-iota-1.76.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.77 stores/grid/igtf-preinstalled-bundle-iota-1.77.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.78 stores/grid/igtf-preinstalled-bundle-iota-1.78.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.79 stores/grid/igtf-preinstalled-bundle-iota-1.79.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.80 stores/grid/igtf-preinstalled-bundle-iota-1.80.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.81 stores/grid/igtf-preinstalled-bundle-iota-1.81.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.82 stores/grid/igtf-preinstalled-bundle-iota-1.82.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.83 stores/grid/igtf-preinstalled-bundle-iota-1.83.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.84 stores/grid/igtf-preinstalled-bundle-iota-1.84.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.85 stores/grid/igtf-preinstalled-bundle-iota-1.85.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.86 stores/grid/igtf-preinstalled-bundle-iota-1.86.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.87 stores/grid/igtf-preinstalled-bundle-iota-1.87.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.88 stores/grid/igtf-preinstalled-bundle-iota-1.88.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.89 stores/grid/igtf-preinstalled-bundle-iota-1.89.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.90 stores/grid/igtf-preinstalled-bundle-iota-1.90.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.91 stores/grid/igtf-preinstalled-bundle-iota-1.91.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.92 stores/grid/igtf-preinstalled-bundle-iota-1.92.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.93 stores/grid/igtf-preinstalled-bundle-iota-1.93.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.94 stores/grid/igtf-preinstalled-bundle-iota-1.94.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.95 stores/grid/igtf-preinstalled-bundle-iota-1.95.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.96 stores/grid/igtf-preinstalled-bundle-iota-1.96.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.97 stores/grid/igtf-preinstalled-bundle-iota-1.97.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.98 stores/grid/igtf-preinstalled-bundle-iota-1.98.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-iota-1.99 stores/grid/igtf-preinstalled-bundle-iota-1.99.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.101 stores/grid/igtf-preinstalled-bundle-mics-1.101.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.16 stores/grid/igtf-preinstalled-bundle-mics-1.16.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.17 stores/grid/igtf-preinstalled-bundle-mics-1.17.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.18 stores/grid/igtf-preinstalled-bundle-mics-1.18.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.19 stores/grid/igtf-preinstalled-bundle-mics-1.19.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.20 stores/grid/igtf-preinstalled-bundle-mics-1.20.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.21 stores/grid/igtf-preinstalled-bundle-mics-1.21.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.22 stores/grid/igtf-preinstalled-bundle-mics-1.22.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.24 stores/grid/igtf-preinstalled-bundle-mics-1.24.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.25 stores/grid/igtf-preinstalled-bundle-mics-1.25.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.26 stores/grid/igtf-preinstalled-bundle-mics-1.26.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.27 stores/grid/igtf-preinstalled-bundle-mics-1.27.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.28 stores/grid/igtf-preinstalled-bundle-mics-1.28.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.29 stores/grid/igtf-preinstalled-bundle-mics-1.29.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.30 stores/grid/igtf-preinstalled-bundle-mics-1.30.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.31 stores/grid/igtf-preinstalled-bundle-mics-1.31.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.32 stores/grid/igtf-preinstalled-bundle-mics-1.32.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.33 stores/grid/igtf-preinstalled-bundle-mics-1.33.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.34 stores/grid/igtf-preinstalled-bundle-mics-1.34.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.35 stores/grid/igtf-preinstalled-bundle-mics-1.35.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.36 stores/grid/igtf-preinstalled-bundle-mics-1.36.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.37 stores/grid/igtf-preinstalled-bundle-mics-1.37.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.38 stores/grid/igtf-preinstalled-bundle-mics-1.38.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.39 stores/grid/igtf-preinstalled-bundle-mics-1.39.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.40 stores/grid/igtf-preinstalled-bundle-mics-1.40.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.41 stores/grid/igtf-preinstalled-bundle-mics-1.41.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.42 stores/grid/igtf-preinstalled-bundle-mics-1.42.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.43 stores/grid/igtf-preinstalled-bundle-mics-1.43.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.44 stores/grid/igtf-preinstalled-bundle-mics-1.44.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.45 stores/grid/igtf-preinstalled-bundle-mics-1.45.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.46 stores/grid/igtf-preinstalled-bundle-mics-1.46.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.47 stores/grid/igtf-preinstalled-bundle-mics-1.47.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.48 stores/grid/igtf-preinstalled-bundle-mics-1.48.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.49 stores/grid/igtf-preinstalled-bundle-mics-1.49.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.50 stores/grid/igtf-preinstalled-bundle-mics-1.50.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.51 stores/grid/igtf-preinstalled-bundle-mics-1.51.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.52 stores/grid/igtf-preinstalled-bundle-mics-1.52.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.53 stores/grid/igtf-preinstalled-bundle-mics-1.53.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.54 stores/grid/igtf-preinstalled-bundle-mics-1.54.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.55 stores/grid/igtf-preinstalled-bundle-mics-1.55.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.56 stores/grid/igtf-preinstalled-bundle-mics-1.56.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.57 stores/grid/igtf-preinstalled-bundle-mics-1.57.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.58 stores/grid/igtf-preinstalled-bundle-mics-1.58.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.59 stores/grid/igtf-preinstalled-bundle-mics-1.59.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.60 stores/grid/igtf-preinstalled-bundle-mics-1.60.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.61 stores/grid/igtf-preinstalled-bundle-mics-1.61.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.62 stores/grid/igtf-preinstalled-bundle-mics-1.62.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.63 stores/grid/igtf-preinstalled-bundle-mics-1.63.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.64 stores/grid/igtf-preinstalled-bundle-mics-1.64.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.65 stores/grid/igtf-preinstalled-bundle-mics-1.65.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.67 stores/grid/igtf-preinstalled-bundle-mics-1.67.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.68 stores/grid/igtf-preinstalled-bundle-mics-1.68.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.69 stores/grid/igtf-preinstalled-bundle-mics-1.69.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.70 stores/grid/igtf-preinstalled-bundle-mics-1.70.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.71 stores/grid/igtf-preinstalled-bundle-mics-1.71.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.72 stores/grid/igtf-preinstalled-bundle-mics-1.72.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.73 stores/grid/igtf-preinstalled-bundle-mics-1.73.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.74 stores/grid/igtf-preinstalled-bundle-mics-1.74.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.75 stores/grid/igtf-preinstalled-bundle-mics-1.75.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.76 stores/grid/igtf-preinstalled-bundle-mics-1.76.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.77 stores/grid/igtf-preinstalled-bundle-mics-1.77.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.78 stores/grid/igtf-preinstalled-bundle-mics-1.78.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.79 stores/grid/igtf-preinstalled-bundle-mics-1.79.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.80 stores/grid/igtf-preinstalled-bundle-mics-1.80.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.81 stores/grid/igtf-preinstalled-bundle-mics-1.81.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.82 stores/grid/igtf-preinstalled-bundle-mics-1.82.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.83 stores/grid/igtf-preinstalled-bundle-mics-1.83.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.84 stores/grid/igtf-preinstalled-bundle-mics-1.84.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.85 stores/grid/igtf-preinstalled-bundle-mics-1.85.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.86 stores/grid/igtf-preinstalled-bundle-mics-1.86.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.87 stores/grid/igtf-preinstalled-bundle-mics-1.87.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.88 stores/grid/igtf-preinstalled-bundle-mics-1.88.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.89 stores/grid/igtf-preinstalled-bundle-mics-1.89.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.90 stores/grid/igtf-preinstalled-bundle-mics-1.90.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.91 stores/grid/igtf-preinstalled-bundle-mics-1.91.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.92 stores/grid/igtf-preinstalled-bundle-mics-1.92.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.93 stores/grid/igtf-preinstalled-bundle-mics-1.93.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.94 stores/grid/igtf-preinstalled-bundle-mics-1.94.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.95 stores/grid/igtf-preinstalled-bundle-mics-1.95.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.96 stores/grid/igtf-preinstalled-bundle-mics-1.96.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.97 stores/grid/igtf-preinstalled-bundle-mics-1.97.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.98 stores/grid/igtf-preinstalled-bundle-mics-1.98.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-mics-1.99 stores/grid/igtf-preinstalled-bundle-mics-1.99.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.1 stores/grid/igtf-preinstalled-bundle-slcs-1.1.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.10 stores/grid/igtf-preinstalled-bundle-slcs-1.10.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.101 stores/grid/igtf-preinstalled-bundle-slcs-1.101.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.11 stores/grid/igtf-preinstalled-bundle-slcs-1.11.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.12 stores/grid/igtf-preinstalled-bundle-slcs-1.12.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.13 stores/grid/igtf-preinstalled-bundle-slcs-1.13.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.14 stores/grid/igtf-preinstalled-bundle-slcs-1.14.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.15 stores/grid/igtf-preinstalled-bundle-slcs-1.15.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.16 stores/grid/igtf-preinstalled-bundle-slcs-1.16.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.17 stores/grid/igtf-preinstalled-bundle-slcs-1.17.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.18 stores/grid/igtf-preinstalled-bundle-slcs-1.18.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.19 stores/grid/igtf-preinstalled-bundle-slcs-1.19.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.2 stores/grid/igtf-preinstalled-bundle-slcs-1.2.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.20 stores/grid/igtf-preinstalled-bundle-slcs-1.20.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.21 stores/grid/igtf-preinstalled-bundle-slcs-1.21.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.22 stores/grid/igtf-preinstalled-bundle-slcs-1.22.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.24 stores/grid/igtf-preinstalled-bundle-slcs-1.24.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.25 stores/grid/igtf-preinstalled-bundle-slcs-1.25.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.26 stores/grid/igtf-preinstalled-bundle-slcs-1.26.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.27 stores/grid/igtf-preinstalled-bundle-slcs-1.27.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.28 stores/grid/igtf-preinstalled-bundle-slcs-1.28.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.29 stores/grid/igtf-preinstalled-bundle-slcs-1.29.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.30 stores/grid/igtf-preinstalled-bundle-slcs-1.30.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.31 stores/grid/igtf-preinstalled-bundle-slcs-1.31.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.32 stores/grid/igtf-preinstalled-bundle-slcs-1.32.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.33 stores/grid/igtf-preinstalled-bundle-slcs-1.33.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.34 stores/grid/igtf-preinstalled-bundle-slcs-1.34.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.35 stores/grid/igtf-preinstalled-bundle-slcs-1.35.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.36 stores/grid/igtf-preinstalled-bundle-slcs-1.36.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.37 stores/grid/igtf-preinstalled-bundle-slcs-1.37.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.38 stores/grid/igtf-preinstalled-bundle-slcs-1.38.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.39 stores/grid/igtf-preinstalled-bundle-slcs-1.39.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.4 stores/grid/igtf-preinstalled-bundle-slcs-1.4.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.40 stores/grid/igtf-preinstalled-bundle-slcs-1.40.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.41 stores/grid/igtf-preinstalled-bundle-slcs-1.41.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.42 stores/grid/igtf-preinstalled-bundle-slcs-1.42.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.43 stores/grid/igtf-preinstalled-bundle-slcs-1.43.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.44 stores/grid/igtf-preinstalled-bundle-slcs-1.44.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.45 stores/grid/igtf-preinstalled-bundle-slcs-1.45.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.46 stores/grid/igtf-preinstalled-bundle-slcs-1.46.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.47 stores/grid/igtf-preinstalled-bundle-slcs-1.47.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.48 stores/grid/igtf-preinstalled-bundle-slcs-1.48.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.49 stores/grid/igtf-preinstalled-bundle-slcs-1.49.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.5 stores/grid/igtf-preinstalled-bundle-slcs-1.5.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.50 stores/grid/igtf-preinstalled-bundle-slcs-1.50.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.51 stores/grid/igtf-preinstalled-bundle-slcs-1.51.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.52 stores/grid/igtf-preinstalled-bundle-slcs-1.52.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.53 stores/grid/igtf-preinstalled-bundle-slcs-1.53.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.54 stores/grid/igtf-preinstalled-bundle-slcs-1.54.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.55 stores/grid/igtf-preinstalled-bundle-slcs-1.55.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.56 stores/grid/igtf-preinstalled-bundle-slcs-1.56.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.57 stores/grid/igtf-preinstalled-bundle-slcs-1.57.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.58 stores/grid/igtf-preinstalled-bundle-slcs-1.58.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.59 stores/grid/igtf-preinstalled-bundle-slcs-1.59.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.6 stores/grid/igtf-preinstalled-bundle-slcs-1.6.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.60 stores/grid/igtf-preinstalled-bundle-slcs-1.60.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.61 stores/grid/igtf-preinstalled-bundle-slcs-1.61.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.62 stores/grid/igtf-preinstalled-bundle-slcs-1.62.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.63 stores/grid/igtf-preinstalled-bundle-slcs-1.63.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.64 stores/grid/igtf-preinstalled-bundle-slcs-1.64.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.65 stores/grid/igtf-preinstalled-bundle-slcs-1.65.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.67 stores/grid/igtf-preinstalled-bundle-slcs-1.67.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.68 stores/grid/igtf-preinstalled-bundle-slcs-1.68.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.69 stores/grid/igtf-preinstalled-bundle-slcs-1.69.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.7 stores/grid/igtf-preinstalled-bundle-slcs-1.7.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.70 stores/grid/igtf-preinstalled-bundle-slcs-1.70.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.71 stores/grid/igtf-preinstalled-bundle-slcs-1.71.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.72 stores/grid/igtf-preinstalled-bundle-slcs-1.72.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.73 stores/grid/igtf-preinstalled-bundle-slcs-1.73.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.74 stores/grid/igtf-preinstalled-bundle-slcs-1.74.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.75 stores/grid/igtf-preinstalled-bundle-slcs-1.75.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.76 stores/grid/igtf-preinstalled-bundle-slcs-1.76.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.77 stores/grid/igtf-preinstalled-bundle-slcs-1.77.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.78 stores/grid/igtf-preinstalled-bundle-slcs-1.78.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.79 stores/grid/igtf-preinstalled-bundle-slcs-1.79.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.8 stores/grid/igtf-preinstalled-bundle-slcs-1.8.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.80 stores/grid/igtf-preinstalled-bundle-slcs-1.80.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.81 stores/grid/igtf-preinstalled-bundle-slcs-1.81.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.82 stores/grid/igtf-preinstalled-bundle-slcs-1.82.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.83 stores/grid/igtf-preinstalled-bundle-slcs-1.83.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.84 stores/grid/igtf-preinstalled-bundle-slcs-1.84.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.85 stores/grid/igtf-preinstalled-bundle-slcs-1.85.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.86 stores/grid/igtf-preinstalled-bundle-slcs-1.86.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.87 stores/grid/igtf-preinstalled-bundle-slcs-1.87.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.88 stores/grid/igtf-preinstalled-bundle-slcs-1.88.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.89 stores/grid/igtf-preinstalled-bundle-slcs-1.89.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.9 stores/grid/igtf-preinstalled-bundle-slcs-1.9.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.90 stores/grid/igtf-preinstalled-bundle-slcs-1.90.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.91 stores/grid/igtf-preinstalled-bundle-slcs-1.91.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.92 stores/grid/igtf-preinstalled-bundle-slcs-1.92.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.93 stores/grid/igtf-preinstalled-bundle-slcs-1.93.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.94 stores/grid/igtf-preinstalled-bundle-slcs-1.94.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.95 stores/grid/igtf-preinstalled-bundle-slcs-1.95.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.96 stores/grid/igtf-preinstalled-bundle-slcs-1.96.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.97 stores/grid/igtf-preinstalled-bundle-slcs-1.97.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.98 stores/grid/igtf-preinstalled-bundle-slcs-1.98.ca
mx-run -Ilib CertReader::App::ImportStore --rootstore grid --tag grid-igtf-slcs-1.99 stores/grid/igtf-preinstalled-bundle-slcs-1.99.ca



# Governmental CAs
mx-run -Ilib CertReader::App::ImportStore --rootstore us_fpki --tag us_fpki stores/country-specific/us_fpki/fcpca.pem
# no specific intermediate
#
mx-run -Ilib CertReader::App::ImportStore --rootstore swiss_gov --tag swiss_gov stores/country-specific/swiss_gov/ca.0
mx-run -Ilib CertReader::App::ImportStoreIntermediates --tag swiss_gov stores/country-specific/swiss_gov/intermediates/intermediates.0
#
mx-run -Ilib CertReader::App::ImportStore --rootstore nl_gov --tag nl_gov stores/country-specific/nl_gov/ca.0
mx-run -Ilib CertReader::App::ImportStoreIntermediates --tag nl_gov stores/country-specific/nl_gov/intermediates/intermediates.0
#
mx-run -Ilib CertReader::App::ImportStore --rootstore au_gov --tag au_gov stores/country-specific/au_gov/ca.0
mx-run -Ilib CertReader::App::ImportStoreIntermediates --tag au_gov stores/country-specific/au_gov/intermediates.0
#
mx-run -Ilib CertReader::App::ImportStore --rootstore india_gov --tag india_gov stores/country-specific/india_gov/ca.0
#
mx-run -Ilib CertReader::App::ImportStore --rootstore oman_gov --tag oman_gov stores/country-specific/oman_gov/ca.0
mx-run -Ilib CertReader::App::ImportStoreIntermediates --tag oman_gov stores/country-specific/oman_gov/intermediates.0
#
mx-run -Ilib CertReader::App::ImportStore --rootstore japan_gov --tag japan_gov stores/country-specific/japan_gov/ca.0
#
mx-run -Ilib CertReader::App::ImportStore --rootstore estonia_sk --tag estonia_sk stores/country-specific/estonia_sk/ca.0
mx-run -Ilib CertReader::App::ImportStoreIntermediates --tag estonia_sk stores/country-specific/estonia_sk/intermediates.0
