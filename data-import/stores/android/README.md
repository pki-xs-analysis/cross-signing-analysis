# Android CA root store

Relevant tags for the downloader tool are, e.g., available from the [Android Documentation](https://source.android.com/setup/start/build-numbers)

Independent of the tags, one could also use the git history:
https://android.googlesource.com/platform/system/ca-certificates/+log/master/files
https://android.googlesource.com/platform/libcore/+log/master/luni/src/main/files/cacerts
https://android.googlesource.com/platform/libcore/+log/master/security/src/main/files/cacerts

## Since Android 7

Since Android 7, root certificates included in Android can be found in the [Android source code repository](https://android.googlesource.com/platform/system/ca-certificates/+/master/files/). Corresponding certificates of older versions can be found in the corresponding branches/tags.
We can also download an archive with [all certificate files](https://android.googlesource.com/platform/system/ca-certificates/+archive/master/files.tar.gz).

## Pre Android 7

With Android 7, the root certificates have been moved with [commit](https://android.googlesource.com/platform/libcore/+/2e2dbe9a15b1f41c311f39aebbb2a843c81994e7) which became effective in [android-7.0.0_r1](https://android.googlesource.com/platform/libcore/+log/android-7.0.0_r1/luni/src/main/files) .
For prior versions, the root certificates have been located in a subtree of [libcore](https://android.googlesource.com/platform/libcore/+/android-6.0.1_r31/luni/src/main/files/cacerts/).


## Additional Links

[Digicert information on Android root certificates](https://www.digicert.com/blog/official-list-trusted-root-certificates-android/)
