CC=emcc
OLEVEL=3
NAME=cipher

all: wasm py cli

wasm:
	@echo "** emscripten (emcc) needs to be installed : https://emscripten.org/docs/getting_started/downloads.html"
	@echo "** Building $(NAME)"	
	$(CC) cipher.cpp -s -s WASM=1 -s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 -s "EXPORTED_FUNCTIONS=['_encrypt','_decrypt']" -s "EXPORTED_RUNTIME_METHODS=['ccall']" -s EXPORT_NAME="$(NAME)" -O$(OLEVEL) -o $(NAME).js
	mv $(NAME).js docs/
	mv $(NAME).wasm docs/

py:
	g++ cipher.cpp -c -D PYTHON -I /usr/include/python3* -s -o py_cipher/cipher -O$(OLEVEL)

cli:
	g++ cipher.cpp -D CLI -s -o cipher -O$(OLEVEL)
