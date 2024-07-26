# PKI Generator
# (c) 2024 Massimiliano Pala
# All Rights Reserved

.PHONY: all

all:
	@./bin/gen-pki.sh

build:
	@cd src && make

clean:
	@rm -rf	PKIs
	@cd src && make clean

distclean: clean

