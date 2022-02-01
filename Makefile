CC=emcc
OLEVEL=3
NAME=cipher

all: wasm py

wasm:
	@echo "** emscripten (emcc) needs to be installed : https://emscripten.org/docs/getting_started/downloads.html"
	@echo "** Building $(NAME)"	
	$(CC) cipher.cc -s -s WASM=1 -s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 -s "EXPORTED_FUNCTIONS=['_encrypt','_decrypt']" -s "EXPORTED_RUNTIME_METHODS=['ccall']" -s EXPORT_NAME="$(NAME)" -Wno-return-stack-address -O$(OLEVEL) -o $(NAME).js
	mv $(NAME).js docs/
	mv $(NAME).wasm docs/

py:
	g++ cipher.cc -s -o py_cipher/cipher -O$(OLEVEL)
