#!/bin/bash

#
# Because there are no Erlang-type ref support in current erlangdomain module,
# we use C-types and C-type references. One looks like :c:type:`typename`
# When building from Edoc output looks like :c:type:`typename()`
# We change it to :c:type:`typename`()
#
FIND=':c:type:\`\([\w\d_]+\)\\(\\)\`'
REPLACE=':c:type:\`\\1\`\\(\\)'
for f in `ls source/*.rst`; do
    #grep -P "$FIND" $f
    #sed 's/:c:type:`[A-Za-z0-9_]{1-50}/---/g' $f > $f.out
    #gawk '{ FS="\n"; print gensub(/:c:type:`([\w\d_]*)\(\)`/, ":c:type:`\\1`()", "g", $1); }' $f > $f.out
    #gawk '{ FS="\n"; print gensub(/:c:type:`[\w\d_]+/, "---", "g", $1); }' $f > $f.out
    env python before-make.py $f $f
done