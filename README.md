[![Build Status](https://travis-ci.org/jonasschnelli/chacha20poly1305.svg?branch=master)](https://travis-ci.org/jonasschnelli/chacha20poly1305) 

chacha20poly1305@bitcoin AEAD
=====

Simple C module for ChaCha20Poly1305@bitcoin AEAD

Features:
* Simple, pure C code without any dependencies.


Build steps
-----------

Object code:

    $ gcc -lm -O3 -c poly1305.c chacha.c chachapoly_aead.c

Tests:

    $ gcc -O3 poly1305.c chacha.c chachapoly_aead.c tests.c -o test

Benchmark:

    $ gcc -lm -O3 poly1305.c chacha.c chachapoly_aead.c bench.c -o bench
    