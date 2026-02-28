.PHONY: all

all: bin/myproxy	

bin/myproxy: src/myproxy.c
	mkdir -p bin/
	gcc src/myproxy.c -o bin/myproxy

clean:
	rm -rf bin/*
	rm -f pjha2.tar.gz

.PHONY: submission
submission: pjha2.tar.gz

pjha2.tar.gz: src/myproxy.c Makefile Readme
	tar czvf $@ Makefile Readme bin/ src/
