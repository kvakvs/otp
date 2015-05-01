#!/bin/sh

cd ..
for wild in "*.cpp" "*.h" "*.c" ; do
    echo "===> $wild"
    astyle --indent=spaces=2 --style=stroustrup \
	--add-brackets \
	--max-code-length=100 \
	--break-blocks \
	--convert-tabs \
	--align-pointer=name \
	--pad-oper \
	--pad-header \
	--unpad-paren \
	-r "$wild"
done