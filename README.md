<div id="table-of-contents">
<h2>Table of Contents</h2>
<div id="text-table-of-contents">
<ul>
<li><a href="#sec-1">1. Install</a></li>
<li><a href="#sec-2">2. Hacking</a></li>
</ul>
</div>
</div>


The go-cryptsetup package is designed to provide golang bindings to
the cryptsetup library. The cryptsetup library is what provides
access to encrypted hard drives on the linux kernel and provides
some of the best encryption for protecting a hard drive from an
attacker with physical access to the device (and not enough time for
a full firmware hack plus arranging for the unsuspecting user to
enter their password).

# Install<a id="sec-1" name="sec-1"></a>

This project can be easily installed with just

    go get -u github.com/kcolford/go-cryptsetup

# Hacking<a id="sec-2" name="sec-2"></a>

The project is maintained on Github. Pull requests will gladly be
accepted.

Please remember to run `go generate` to rebuild the generated source
code. The generated files are committed to the repository as per the
recommendations of the Go documentation.
