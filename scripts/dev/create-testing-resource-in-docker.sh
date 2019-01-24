#!/usr/bin/env bash

auth_public_jwk=$1

if [[ "help" == "$1" ]] || [[ "" == "$1" ]]; then
    echo "Usage:"
    echo bash $0 "<auth-public-jwk> [<resource-meta-json-file|resource-meta-json>]"
    exit 0
fi
if [[ "" == "$2" ]]; then
    resource_meta=$(awk '{printf "%s", $0}' $(dirname ${0})'/default-testing-resource-meta.json')
elif [[ -f "$2" ]]; then
    resource_meta=$(awk '{printf "%s", $0}' ${2})
else
    resource_meta=${2}
fi


resource_meta=$(awk '{printf "%s", $0}' $(dirname ${0})'/default-testing-resource-meta.json')
signing_jwk=$(awk '{printf "%s", $0}' $(dirname ${0})'/signing-jwk.json')

r=$(docker exec -it `docker ps -f name=hydra_hydra_1 -q` \
hydra resources put \
--endpoint "http://localhost:4444" \
--resource-metadata "${resource_meta}" \
--auth-public-jwk "${auth_public_jwk}" \
--signing-jwk "${signing_jwk}" \
--user foo.bar --pwd secret \
)

next_command=$(echo ${r} | grep commit | awk -F'"' '{print $2}')
urn=$(echo ${next_command} | awk -F'--urn' '{print $2}' | awk '{print $1}')

if [[ "" == ${next_command} ]]
then
    echo  "${r}"
    exit 1
fi

read -p "Enter resource '${urn}' commit_code: " commit_code

if [[ "" == "$commit_code" ]]
then
    echo  "error: empty commit_code"
    exit 1
fi

next_command="${next_command//<COMMIT_CODE>/$commit_code}"

docker exec -it `docker ps -f name=hydra_hydra_1 -q` ${next_command}