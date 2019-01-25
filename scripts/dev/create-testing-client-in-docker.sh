#!/usr/bin/env bash

supported_scopes () {
    scp=$(curl http://localhost:4444/.well-known/oauth-authorization-server \
        | awk -F '"signed_metadata"' '{print $2}' \
        | awk -F '"' '{print $2}' \
        | awk -F '.' '{print $2}' \
        | base64 -D \
        | awk -F '"scopes_supported"' '{print $2}' \
        | awk -F '[' '{print $2}' \
        | awk -F ']' '{print $1}' \
        | sed 's/"//g' \
    )
    echo ${scp}
}

auth_public_jwk=$1

if [[ "help" == "$1" ]] || [[ "" == "$1" ]]
then
    echo "Usage:"
    echo bash $0 "<auth-public-jwk> [<>]"
    exit 0
fi

while [[ "${client_type}" != "1" ]] && [[ "${client_type}" != "2" ]]
do
    echo "Select client type:"
    echo "( 1 ) Public client"
    echo "( 2 ) Confidential client"
    read -p "1 - 2: " client_type
done

client_id=$(uuidgen)
signing_jwk=$(awk '{printf "%s", $0}' $(dirname ${0})'/json/signing-jwk.json')


if [[ "${client_type}" == "1" ]]; then
    while [[ "${client_profile}" != "1" ]] && [[ "${client_profile}" != "2" ]]
    do
        echo "Select client profile:"
        echo "( 1 ) User Agent Based (e.g Browser)"
        echo "( 2 ) Native Application (e.g Mobile App)"
        read -p "1 - 2: " client_profile
    done
    if [[ "${client_profile}" == "1" ]]; then
        client_profile="user-agent-based"
        grant_types_arg='--grant-types "implicit" --grant-types "urn:ietf:params:oauth:grant-type:jwt-bearer" '

    elif [[ "${client_profile}" == "2" ]]; then
        client_profile="native"
        grant_types_arg='--grant-types "implicit" --grant-types "urn:ietf:params:oauth:grant-type:jwt-bearer" '
    else
        exit 1
    fi
    scope_arg="$(supported_scopes| sed 's/,/ /g')"

    jwks=$(awk '{printf "%s", $0}' $(dirname ${0})'/json/default-public-client-public-jwkset.json')
    ret=$(docker exec -it `docker ps -f name=hydra_hydra_1 -q` \
         hydra clients put \
         --endpoint "http://localhost:4444" \
         --id "${client_id}" \
         --name "my-app" \
         ${grant_types_arg} \
         --client-uri "http://myapp.com" \
         --contacts "admin@myapp.com" \
         --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
         --software-version "0.0.1" \
         --callbacks "http://myapp.com/oauth/callback" \
         --response-types "token" \
         --response-types "id_token" \
         --scope "${scope_arg}" \
         --id-token-signed-response-alg "ES256" \
         --request-object-signing-alg "ES256" \
         --token-endpoint-auth-method "private_key_jwt+session" \
         --client-profile "${client_profile}" \
         --jwks "${jwks}" \
         --signing-jwk "${signing_jwk}" \
         --auth-public-jwk "${auth_public_jwk}"
    )
    echo  "${ret}"

    success=$(echo "${ret}"| grep 'OAuth 2.0 Signed Client ID:'| awk -F 'OAuth 2.0 Signed Client ID:' '{print $2}'| awk -F '.' '{print $2}'| base64 -D)
    if [[ "${success}" == "" ]]; then
        echo ""
        echo "Error:"
        echo "${ret}"
    else
        echo ${success}
        echo "Success"
        echo Client ID: ${client_id}
        echo Client Private JSON Web Key Set:
        cat  $(dirname ${0})'/json/default-public-client-private-jwkset.json'
    fi

elif [[ "${client_type}" == "2" ]]; then
        while [[ "${client_profile}" != "1" ]] && [[ "${client_profile}" != "2" ]]
    do
        echo "Select client profile:"
        echo "( 1 ) Web Server Application (e.g API service)"
        echo "( 2 ) Batch (e.g BackGround Job)"
        read -p "1 - 2: " client_profile
    done
    if [[ "${client_profile}" == "1" ]]; then
        client_profile="web"
        grant_types_arg='--grant-types "client_credentials"'
    elif [[ "${client_profile}" == "2" ]]; then
        client_profile="batch"
        grant_types_arg='--grant-types "client_credentials" '
    else
        exit 1
    fi
    scope_arg=$(supported_scopes|sed 's/openid,//g' | sed 's/,/ /g')
    jwks=$(awk '{printf "%s", $0}' $(dirname ${0})'/json/default-confidential-client-public-jwkset.json')
    ret=$(docker exec -it `docker ps -f name=hydra_hydra_1 -q` \
      hydra clients put \
     --endpoint "http://localhost:4444" \
     --id "${client_id}" \
     --name "my-app" \
     ${grant_types_arg} \
     --client-uri "http://myapp.com" \
	 --contacts "admin@myapp.com" \
	 --software-id "4d51529c-37cd-424c-ba19-cba742d60903" \
	 --software-version "0.0.1" \
	 --scope "${scope_arg}" \
     --token-endpoint-auth-method "private_key_jwt" \
	 --client-profile "${client_profile}" \
	 --jwks "${jwks}" \
     --signing-jwk "${signing_jwk}"  \
     --auth-public-jwk "${auth_public_jwk}" \
     --user foo.bar \
	 --pwd secret \
	 )
	next_command=$(echo "${ret}"|grep 'clients commit' | awk -F '"' '{print $2}')
    if [[ "${next_command}" == "" ]]; then
        echo ""
        echo "Error:"
        echo "${ret}"
        exit 1
    fi

    read -p "Enter client '${client_id}' commit_code: " commit_code
    if [[ "" == "$commit_code" ]]
    then
        echo  "error: empty commit_code"
        exit 1
    fi

    next_command="${next_command//<COMMIT_CODE>/$commit_code}"
    res=$(docker exec -it `docker ps -f name=hydra_hydra_1 -q` ${next_command})
    success=$(echo "${res}"| grep 'Signed Client Credentials:'| awk -F 'Signed Client Credentials:' '{print $2}'| awk -F '.' '{print $2}'| base64 -D)
    if [[ "${success}" == "" ]]; then
        echo ""
        echo "Error:"
        echo ${res}
        exit
    fi
    echo ""
    echo "Success"
    echo ${success}
    echo Client ID: ${client_id}
    echo Client Private JSON Web Key Set:
    cat  $(dirname ${0})'/json/default-confidential-client-private-jwkset.json'
else
    exit 0
fi
