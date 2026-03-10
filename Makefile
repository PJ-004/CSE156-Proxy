.PHONY: all

all: bin/myproxy	

bin/myproxy: src/myproxy.c
	mkdir -p bin/
	gcc src/myproxy.c -lssl -lcrypto -o bin/myproxy

clean:
	rm -rf bin/*
	rm -f pjha2.tar.gz
	rm -f access.log

.PHONY: submission
submission: pjha2.tar.gz

pjha2.tar.gz: src/myproxy.c Makefile Readme
	tar czvf $@ Makefile Readme bin/ src/

.PHONY: test
test: bin/myproxy
	./bin/myproxy -p 8080 -a doc/forbidden.txt -l access.log
