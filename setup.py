#!/usr/bin/env python3

PKG_DIST = 'py3-libldap'
PKG_NAME = 'libldap'
PKG_VERS = '1.3'

import codecs, os

from setuptools import setup, Extension
from ctypes.util import find_library

HERE = os.path.abspath(os.path.dirname(__file__))

def read(*parts):
    with codecs.open(os.path.join(HERE, *parts), "rb", "utf-8") as f:
        return f.read()
    
define_macros=[('LDAP_DEPRECATED', 1)]
if os.uname()[0] == 'Darwin':
    define_macros.append(('__LIBLDAP_DARWIN__', 1))
    library_dirs=['/usr/local/lib']
else:
    library_dirs=[]

libsasl = find_library('sasl'), find_library('sasl2')
if libsasl != (None, None):
    define_macros.append(('__HAVE_SASL__', 1))
    
libldap_module = Extension(
    '_' + PKG_NAME,
    sources=[
        'C/libldap.c', 'C/LDAPObject.c', 'C/LDAPModObject.c', 'C/LDAPSchema.c',
        'C/LDAPControls.c'
        ],
    depends=[
        'C/libldap.h', 'C/LDAPObject.h', 'C/LDAPModObject.h', 'C/LDAPSchema.h',
        'C/LDAPControls.h'
        ],
    include_dirs=['C', '/usr/local/include'],
    libraries=['ldap'],
    extra_compile_args = ["-fcommon"],
    library_dirs=library_dirs,
    define_macros=define_macros
    )

setup(
    name=PKG_DIST,
    version=PKG_VERS,
    description='OpenLDAP library wrapper',
    long_description=read('README.txt'),
    author='Yves Legrandgerard',
    author_email='ylg@pps.univ-paris-diderot.fr',
    license='DWTFYWT',
    platforms=['Linux', 'FreeBSD'],
    py_modules=['libldap'],
    ext_modules=[libldap_module],
    url='https://github.com/ylgg/libldap',
    include_package_data=True
)
