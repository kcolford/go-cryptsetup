/*
Cryptsetup is designed to facilitate using linux's full disk
encryption.

Some distributions may require you to install the relevent development
libraries. Arch Linux includes all the necessary libraries by default,
although it does not include libcryptsetup.a, the static version of
the library. A modified PKGBUILD can be found in the contrib/
directory that should fix this (it's a relatively fast build time on
an intel celeron).
*/
package cryptsetup
