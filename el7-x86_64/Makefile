CC = cc
SRC = alpn.c clientcert.c options.c session.c ssl.c threads.c util.c
OBJ = $(patsubst %.c, target/%.o, $(SRC))

default: target/classes/el7-x86_64/libwfssl.so

clean:
	rm -rf target

target/classes/el7-x86_64:
	mkdir -p target/classes/el7-x86_64

target/%.o : ../libwfssl/src/%.c target/classes/el7-x86_64
	$(CC) $(CFLAGS) -Werror -Wall -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wpointer-arith -std=c89 -Wdeclaration-after-statement -Wformat -Wformat-security -Wunused -Wno-unknown-pragmas -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

target/classes/el7-x86_64/libwfssl.so: $(OBJ)
	$(CC) $(CFLAGS) -shared $(OBJ) -o $@ $(LDFLAGS) -Wl,--no-as-needed -ldl
