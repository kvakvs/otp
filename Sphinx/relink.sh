#!/bin/bash

# Deletes *.rst from the source/
# Relinks *.3 from man page directory in erts/doc/man3 as RST files to source/

rm -f source/index.rst
ln -s `pwd`/index.rst source/index.rst

ERTSDOC=`realpath ../erts/doc/man3`
for f in driver_entry erlang erl_driver erl_nif erl_prim_loader erl_tracer erts_alloc init zlib ; do
    rm -f source/$f.rst
    ln -s $ERTSDOC/$f.3 source/$f.rst
done
