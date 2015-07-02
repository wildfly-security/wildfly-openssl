#
#
#

CFILES=$(sort $(wildcard src/*.c))
LINUX_x86_64_OFILES=$(patsubst src/%.c,linux-x86_64/%.o,$(CFILES))
LINUX_i686_OFILES=$(patsubst src/%.c,linux-i686/%.o,$(CFILES))
MAC_OFILES=$(patsubst src/%.c,mac/%.o,$(CFILES))

ALL_OFILES=$(LINUX_x86_64_OFILES) $(LINUX_i686_OFILES) $(MAC_OFILES)

ALL_TARGETS=linux-x86_64/libutssl.so linux-i686/libutssl.so mac/libutssl.dylib

STRIP=strip

default: all

linux: linux-x86_64/libutssl.so linux-i686/libutssl.so

mac: mac/libutssl.dylib

all: linux mac

clean:
	@echo '       rm ' $(ALL_OFILES) $(ALL_TARGETS)
	@$(RM) -f $(ALL_OFILES) $(ALL_TARGETS)

$(ALL_OFILES): Makefile

linux-x86_64/%.o: src/%.c
	@echo '  compile ' $@
	@$(CC) -m64 $< -Iinclude -std=gnu99 -fPIC -g -c -o $@ -O2 -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(JAVA_HOME)/linux/include -Wall -Werror

linux-x86_64/libutssl.so: $(LINUX_x86_64_OFILES)
	@echo '     link ' $@
	@$(CC) -m64 -lcrypto -lssl -shared $(LINUX_x86_64_OFILES) -o $@

linux-i686/%.o: src/%.c
	@echo '  compile ' $@
	@$(CC) -m32 $< -Iinclude -std=gnu99 -fPIC -g -c -o $@ -O2 -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux -I$(JAVA_HOME)/linux/include -Wall -Werror

linux-i686/libutssl.so: $(LINUX_i686_OFILES)
	@echo '     link ' $@
	@$(CC) -m32  -lcrypto -lssl -shared $(LINUX_i686_OFILES) -o $@

mac/%.o: src/%.c
	@echo '  compile ' $@
	@$(CC) -m64 $< -Iinclude -std=gnu99 -fPIC -g -c -o $@ -O2 -I$(JAVA_HOME)/include -Wall -Werror

mac/libutssl.dylib: $(MAC_OFILES)
	@echo '     link ' $@
	@$(CC) -m64  -lcrypto -lssl -dynamiclib $(MAC_OFILES) -o $@