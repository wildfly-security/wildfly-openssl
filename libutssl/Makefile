#
#
#

CFILES=$(sort $(wildcard src/*.c))
LINUX_x86_64_OFILES=$(patsubst src/%.c,linux-x86_64/%.o,$(CFILES))
MAC_OFILES=$(patsubst src/%.c,mac/%.o,$(CFILES))

ALL_OFILES=$(LINUX_x86_64_OFILES) $(MAC_OFILES)

ALL_TARGETS=linux-x86_64/libutssl.so mac/libutssl.dylib

STRIP=strip

CFLAGS=-D_REENTRANT -I/usr/local/opt/openssl/include

default: all

linux: linux-x86_64/libutssl.so

mac: mac/libutssl.dylib

all: linux mac

clean:
	@echo '       rm ' $(ALL_OFILES) $(ALL_TARGETS)
	@$(RM) -f $(ALL_OFILES) $(ALL_TARGETS)

$(ALL_OFILES): Makefile

linux-x86_64/%.o: src/%.c
	@echo '  compile ' $@
	@$(CC) $(CFLAGS) -m64 $< -Iinclude -std=gnu99 -fPIC -g -c -o $@ -O2 -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(JAVA_HOME)/linux/include -Wall -Werror

linux-x86_64/libutssl.so: $(LINUX_x86_64_OFILES)
	@echo '     link ' $@
	@$(CC)  -L/usr/local/opt/openssl/lib -m64 -shared $(LINUX_x86_64_OFILES) -o $@

mac/%.o: src/%.c
	@echo '  compile ' $@
	@$(CC) $(CFLAGS) -m64 $< -Iinclude -std=gnu99 -fPIC -g -c -o $@ -O2 -I$(JAVA_HOME)/include -Wall -Werror

mac/libutssl.dylib: $(MAC_OFILES)
	@echo '     link ' $@
	@$(CC) -L/usr/local/opt/openssl/lib -m64 -dynamiclib $(MAC_OFILES) -o $@
