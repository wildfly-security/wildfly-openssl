
SRC = alpn.c clientcert.c options.c session.c ssl.c threads.c util.c
OBJ = $(patsubst %.c, target/%.o, $(SRC))

default: target/classes/macosx-x86_64/libwfssl.dylib

clean:
	rm -rf target

target/classes/macosx-x86_64:
	mkdir -p target/classes/macosx-x86_64

target/%.o : ../libwfssl/src/%.c target/classes/macosx-x86_64
	cc -Werror -Wall -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations -Wpointer-arith -std=c89 -Wdeclaration-after-statement -Wformat -Wformat-security -Wunused -Wno-unknown-pragmas -c $< -o $@ -I../libwfssl/include

target/classes/macosx-x86_64/libwfssl.dylib: $(OBJ)
	cc -dynamiclib $(OBJ) -o $@
