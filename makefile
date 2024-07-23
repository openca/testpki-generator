# PKI Generator
# (c) 2024 Massimiliano Pala
# All Rights Reserved

.PHONY: all

all:
	@./gen-pki.sh

clean:
	@rm -rf PKIs

distclean: clean

