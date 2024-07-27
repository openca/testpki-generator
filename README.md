# PKI Generator

This package is provided as a tool to quickly generate full PKI infrastructure
that can be use for TLS testing. The issued certificates use minimal profiles
to ensure (a) no-expiration, and (b) compatibility.

## PKI Gen Script Usage

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

## TLS Example Server

### Build

This pacakge builds a client/server implementation to demonstrate the use of
hybrid technologies for Enterprise TLS (i.e., non-browser traffic). To build
the software, please use the following

```bash
$ make build
```

Please make sure you fix/update the directories in the makefile to correctly
find the headers and the libraries to be linked.

### Usage

To start the server, you can use any of the examples/ or the PKIs/ directories
credentials by simply providing the directory where to load the chain and
private key from:

```bash
$ src/mermaid-server examples/comp-1
```

The client implementation is also available. The first argument is the same
as the server's use case, however the client also requires the `server_name`
and the `server_port` parameters.

For example, to connect to locahost at port 4433, you can run:

```bash
$ src/mermaid-client examples/comp-1 localhost 4433
```

## Support

Please direct all your inquiries at Dr. Pala `<director@openca.org>`

Enjoy PKIs!
Dr. Pala
