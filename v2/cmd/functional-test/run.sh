#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest-8-cores" ];then
    extension=.exe
fi

echo "::group::Building functional-test binary"
go build -o functional-test$extension
echo "::endgroup::"

echo "::group::Building Nuclei binary from current branch"
go build -o gosecurity_dev$extension ../gosecurity
echo "::endgroup::"

echo "::group::Installing gosecurity templates"
./gosecurity_dev$extension -update-templates
echo "::endgroup::"

echo "::group::Building latest release of gosecurity"
go build -o gosecurity$extension -v github.com/doapply/gosecurity/v2/cmd/gosecurity
echo "::endgroup::"

echo 'Starting Nuclei functional test'
./functional-test$extension -main ./gosecurity$extension -dev ./gosecurity_dev$extension -testcases testcases.txt
