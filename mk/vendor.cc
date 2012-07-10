#!/bin/sh

set -e 

: ${CC:=cc}

${CC} -E - <<-EOF | grep -v \#
	#if defined __SUNPRO_C
	sunpro
	#elif defined __clang__
	clang
	#elif defined __GNUC__
	gcc
	#else
	other
	#endif
EOF
