CC=emcc
OLEVEL=3
NAME=cipher

all: wasm py cli

wasm:
	@echo "** emscripten (emcc) needs to be installed : https://emscripten.org/docs/getting_started/downloads.html"
	@echo "** Building $(NAME)"	
	$(CC) cipher.cpp -DWASM -s -s WASM=1 -s NO_EXIT_RUNTIME=1 -s MODULARIZE=1 -s "EXPORTED_FUNCTIONS=['_encrypt','_decrypt']" -s "EXPORTED_RUNTIME_METHODS=['ccall']" -s EXPORT_NAME="$(NAME)" -O$(OLEVEL) -o $(NAME).js
	mv $(NAME).js docs/
	mv $(NAME).wasm docs/

py:
	rm -f pycipher/*.so
	python setup.py build

cli:
	g++ cipher.cpp -DCLI -s -o cipher -O$(OLEVEL)
