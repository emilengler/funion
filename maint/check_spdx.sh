#!/usr/bin/env bash 
# SPDX-License-Identifier: ISC

SPDX="# SPDX-License-Identifier: ISC"

elixir=( $(find apps/ -type f -name "*.ex*") )
shell=( $(find maint/ -type f -name "*.sh") )

exit_code=0

for f in ${elixir[@]}
do
	if [[ "$(head -n1 $f)" != "$SPDX" ]];
	then
		echo $f
		exit_code=1
	fi
done

for f in ${shell[@]}
do
	if [[ "$(head -n2 $f | tail -n1)" != "$SPDX" ]];
	then
		echo $f
		exit_code=1
	fi
done

exit $exit_code
