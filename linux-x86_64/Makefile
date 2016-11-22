
SRC = alpn.c clientcert.c options.c session.c ssl.c threads.c util.c
OBJ = $(patsubst %.c, target/%.o, $(SRC))

default: target/classes/linux-x86_64/libwfssl.so

clean:
	rm -rf target

target/classes/linux-x86_64:
	mkdir -p target/classes/linux-x86_64

target/%.o : ../libwfssl/src/%.c target/classes/linux-x86_64
	cc -fPIC -c $< -o $@ -I../libwfssl/include -I$(JAVA_HOME)/include -I$(JAVA_HOME)/include/linux

target/classes/linux-x86_64/libwfssl.so: $(OBJ)
	cc -shared $(OBJ) -o $@ -Wl,--no-as-needed -ldl
