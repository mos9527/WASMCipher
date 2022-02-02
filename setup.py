from distutils.core import setup, Extension

module1 = Extension('cipher',
                    sources = ['cipher.cpp'])

setup (name = 'cipher',
       version = '1.0',
       description = 'This is a demo package for cipher.cc',
       ext_modules = [module1])