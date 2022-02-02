from distutils.core import setup, Extension

exts = Extension('cipher',sources = ['cipher.cpp'], define_macros=[('PYTHON','')],)

setup (name = 'pycipher',
       version = '1.0',
       description = 'WASMCipher native Python bindings',
       ext_modules = [exts],
       options={'build':{'build_lib':'./pycipher'}})