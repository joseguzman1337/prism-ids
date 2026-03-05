#!/bin/bash

set -euo pipefail

exec 1>&2

# We use traps to set the failed variable to "yes" for failed mandatory checks
failed=no

function mandatory()
{
	set +e
	trap 'failed=yes' ERR
	"$@"
	trap - ERR
	set -e
}

echo 'Running mypy'
mandatory mypy

echo 'Running Flake8'
mandatory flake8

echo 'Running Python Unittests (with coverage)'
mandatory nose2

if [ "${failed}" != 'no' ]; then
	echo 'Mandatory code-check failed'
	exit 1
fi

echo 'Coverage report'
exec coverage report -m
