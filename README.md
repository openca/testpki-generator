# PKI Generator

This package is provided as a tool to quickly generate full PKI infrastructure
that can be use for TLS testing. The issued certificates use minimal profiles
to ensure (a) no-expiration, and (b) compatibility.

## Usage

This package uses a makefile to execute the gen-pki.sh script. The script loads
the parameters' files (one at a time) and generates the PKI according to the
provided parameters.

New PKIs are defined via additional parameters' files where the configuration
for the Root, Intermediate, and End Entity certificates. When the script is
executed, each of the parameters' files is executed and the configured PKI is
issued: private keys, certificates, and convenient chain files.

To generate all configured PKIs, simply use the makefile default target:

```bash
$ make
Loading params/comp-1-params.sh ...
Loading params/comp-2-params.sh ...
Loading params/pqc-1-params.sh ...
Loading params/trad-1-params.sh ...
Loading params/trad-2-params.sh ...
$
```

The defaul example PKIs' artifacts are provided as an example in the examples/
directory of the repository.

## Support

Please direct all your inquiries at Dr. Pala `<director@openca.org>`

Enjoy PKIs!
Dr. Pala

