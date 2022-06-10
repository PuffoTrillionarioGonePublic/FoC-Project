# Inspired by:
# http://retis.santannapisa.it/luca/makefiles.pdf
# Example:
# http://retis.santannapisa.it/luca/SDDL/Hello/Makefile.gnu

CC=g++-11
CPPFLAGS+=-Wall -Wextra -std=c++20
LDLIBS=-lcrypto -lpthread

FILES=main.cc
DEPS=$(FILES:.cc=.d)
OBJS=$(FILES:.cc=.o)

main: $(OBJS)

build: main

.PHONY: rebuild
rebuild: clean build

.PHONY: clean
clean:
	rm -f main *.o *.d

%.d: %.cc
	$(CC) -MM -MF $@ $<
-include $(DEPS)

.PHONY: run
run: main
	./main
