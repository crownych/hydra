#!/bin/bash -e -o pipefail

sts_session_name=TravisDeploy-$(echo $TRAVIS_REPO_SLUG | tr -dc '[:alnum:]\n\r' | cut -b 1-50 )

accountid=$( aws sts get-caller-identity | jq -r .Account )
temp_role=$( aws sts assume-role --role-arn arn:aws:iam::$accountid:role/$ROLE_NAME --role-session-name $sts_session_name )
export AWS_ACCESS_KEY_ID=$( echo $temp_role | jq -r .Credentials.AccessKeyId )
export AWS_SECRET_ACCESS_KEY=$( echo $temp_role | jq -r .Credentials.SecretAccessKey )
export AWS_SESSION_TOKEN=$( echo $temp_role | jq -r .Credentials.SessionToken )
export AWS_ACCOUNTID=$accountid
