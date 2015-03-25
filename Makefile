# In the gcc man page, the "overall options" include "-c" for
# compiling but not linking.
#
all : nm_create_server_keys nm_sign shatest nm_verify

shatest : shatest.c
	gcc  -Wall -g -O0 -D_FILE_OFFSET_BITS=64 \
		-o shatest shatest.c /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a

nm_verify : nm_verify.c nm_keys.o nm_keys.c
	gcc  -Wall -g -O0 -D_FILE_OFFSET_BITS=64  \
		-o nm_verify nm_keys.o nm_verify.c /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a


nm_sign : nm_sign.c nm_keys.o nm_keys.c
	gcc  -Wall -g -O0 -D_FILE_OFFSET_BITS=64 \
		-o nm_sign nm_keys.o nm_sign.c /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a


nm_create_server_keys : nm_create_server_keys_main.o nm_keys.o
	gcc  -Wall -g -O0 -D_FILE_OFFSET_BITS=64 \
		-o nm_create_server_keys nm_create_server_keys_main.o nm_keys.o /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a


nm_keys.o : nm_keys.h nm_keys.c
	gcc  -c -o nm_keys.o -Wall -g -O0 -D_FILE_OFFSET_BITS=64  \
		nm_keys.c /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a

nm_create_online_key : nm_create_online_key.c nm_keys.o nm_keys.c
	gcc  -Wall -g -O0 -D_FILE_OFFSET_BITS=64 \
	-o nm_create_online_key nm_keys.o nm_create_online_key.c /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a

nm_create_server_keys_main.o : nm_create_server_keys.c nm_keys.o nm_keys.c
	gcc  -c -Wall -g -O0 -D_FILE_OFFSET_BITS=64 \
		-o nm_create_server_keys_main.o nm_create_server_keys.c /usr/local/lib/libgcrypt.a /usr/local/lib/libgpg-error.a

install:
	# For the client, only the nm_verify needs to be installed,
	# the other programs are for veririfcation
	if [ ! -d /usr/local/bin ]; then
		mkdir -p /usr/local/bin
		chmod 755 /usr/local/bin
	fi
	cp nm_verify /usr/local/bin
	chown root /usr/local/bin/nm_verify
	chmod 555 /usr/local/bin/nm_verify
