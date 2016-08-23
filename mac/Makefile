
SRC = alpn.c clientcert.c options.c session.c ssl.c threads.c util.c
OBJ = $(patsubst %.c, target/%.o, $(SRC))

default: target/classes/libwfssl.dylib

clean:
	rm -rf target

target/classes:
	mkdir -p target/classes
	

target/%.o : ../libwfssl/src/%.c target/classes
	cc -c $< -o $@ -I../libwfssl/include -I/usr/local/opt/openssl/include

target/classes/libwfssl.dylib: $(OBJ)
	cc -dynamiclib $(OBJ) -o $@
