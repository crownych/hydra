#!/usr/bin/env bash
set -euo pipefail

function print_function_name(){
    echo "$(tput bold;tput setaf 2 ) === ${FUNCNAME[1]} === $(tput sgr0)"
}

function set_env_var() {
    print_function_name
    
    # Set env varables from cloudformation stack outputs: 
    #   Outputs[].OutputKey==Cluster
    #   Outputs[].OutputKey==Service
    #   Outputs[].OutputKey==ExecutionRole
    #   Outputs[].OutputKey==TaskRole
    #   Outputs[].OutputKey==ElasticContainerRegistry
    #   Outputs[].OutputKey==LogGroup
    #   Outputs[].OutputKey==TaskDefinition
    local outputs=$( aws cloudformation describe-stacks | jq --arg ECS_SERVICE_STACKNAME ${ECS_SERVICE_STACKNAME} -r '.Stacks[] | select(.StackName==$ECS_SERVICE_STACKNAME)|.Outputs[]' )
    export ECS_CLUSTER=$( echo $outputs | jq -r '.| select(.OutputKey=="Cluster") | .OutputValue' )
    export ECS_SERVICE=$( echo $outputs | jq -r '.| select(.OutputKey=="Service") | .OutputValue' | awk -F "/" '{print $NF}' )
    export TASK_DEFINITION_EXECUTION_ROLE_ARN=$( echo $outputs | jq -r '.| select(.OutputKey=="ExecutionRole") | .OutputValue' )
    export TASK_DEFINITION_TASK_ROLE_ARN=$( echo $outputs | jq -r '.| select(.OutputKey=="TaskRole") | .OutputValue' )
    export ECR_URI=$( echo $outputs | jq -r '.| select(.OutputKey=="ElasticContainerRegistry") | .OutputValue' )
    export CLW_LOG_GROUP=$( echo $outputs | jq -r '.| select(.OutputKey=="LogGroup") | .OutputValue' )
    export TASK_DEFINITION_FAMILY=$( echo $outputs | jq -r '.| select(.OutputKey=="TaskDefinition") | .OutputValue'| awk -F "/" '{print $(NF)}' | awk -F ":" '{print $1}' )
    export ECR_URI_TAG_LATEST=${ECR_URI}:latest
    export ECR_URI_TAG_CUSTOM=${ECR_URI}:${TRAVIS_COMMIT}

    # Set ECS task desire-count . Default: 1
    if [[ -z ${TASK_DESIRED_COUNT} ]]; then 
        export TASK_DESIRED_COUNT_CLI="--desired-count 1"
    else 
        export TASK_DESIRED_COUNT_CLI="--desired-count "${TASK_DESIRED_COUNT}
    fi
}

function ecs_register_task_definition() {
    print_function_name

    # Register new version task definition
    local outputs=$(aws ecs register-task-definition \
        --cli-input-json file://${TASK_DEFINITION_TEMPLATE} \
        --family ${TASK_DEFINITION_FAMILY} \
        --execution-role-arn ${TASK_DEFINITION_EXECUTION_ROLE_ARN} \
        --task-role-arn ${TASK_DEFINITION_TASK_ROLE_ARN} )
    echo $( echo $outputs | jq -r '.taskDefinition|"Registered taskdefinition : "+.family+":"+(.revision|tostring)' )
}

function ecs_update_service() {
    print_function_name

    # Update service with new version task definition
    local outputs=$( aws ecs update-service \
        --cluster ${ECS_CLUSTER} \
        --service ${ECS_SERVICE} \
        ${TASK_DESIRED_COUNT_CLI} \
        --task-definition ${TASK_DEFINITION_FAMILY} )
    echo $( echo $outputs | jq -r '.service.deployments' ) | jq -r '.'
    
}

function ecs_wait_services_stable() {
    print_function_name

    aws ecs wait services-stable --services "${ECS_SERVICE}"  --cluster  ${ECS_CLUSTER}
}

function install_tools() {
    print_function_name

    pip install -q --user awscli 
}

function get_sts(){
    print_function_name

    if [[ ${AWS_ACCESS_KEY_ID} == "" ]]; then
        echo "empty AWS_ACCESS_KEY_ID"
        exit 1
    fi

    local sts_session_name=TravisDeploy-$(echo ${TRAVIS_REPO_SLUG} | tr -dc '[:alnum:]\n\r' | cut -b 1-50 )
    local accountid=$( aws sts get-caller-identity | jq -r .Account )
    local temp_role=$( aws sts assume-role --role-arn arn:aws:iam::$accountid:role/${ROLE_NAME} --role-session-name $sts_session_name )

    export AWS_ACCESS_KEY_ID=$( echo $temp_role | jq -r .Credentials.AccessKeyId )
    export AWS_SECRET_ACCESS_KEY=$( echo $temp_role | jq -r .Credentials.SecretAccessKey )
    export AWS_SESSION_TOKEN=$( echo $temp_role | jq -r .Credentials.SessionToken )
    export AWS_ACCOUNT_ID=$accountid
}

function ecr_login() {
    print_function_name

    eval $( aws ecr get-login --no-include-email --region ${AWS_DEFAULT_REGION} )
}

function docker_build_tag_push() {
    print_function_name

    # Build, tag and push image 
    docker build -t image .
    docker tag image:latest ${ECR_URI_TAG_LATEST}
    docker tag image:latest ${ECR_URI_TAG_CUSTOM}
    docker push ${ECR_URI_TAG_LATEST}
    docker push ${ECR_URI_TAG_CUSTOM}
}

function replace_var_in_taskdefinition(){
    print_function_name

    # This will replace '$$ENV_VAR_NAME$$' in ${TASK_DEFINITION_TEMPLATE} with environment variable
    # Example :
    # $$ECR_URI_TAG_CUSTOM$$ : Image with commit sha
    # $$CLW_LOG_GROUP$$ : log group

    str=`cat ${TASK_DEFINITION_TEMPLATE}`
    while [[ $str =~ ('$$'([[:alnum:]_]+)'$$') ]]; do
        str=${str//${BASH_REMATCH[1]}/${!BASH_REMATCH[2]}}
    done
    echo "$str" > ${TASK_DEFINITION_TEMPLATE}

    #cat ${TASK_DEFINITION_TEMPLATE} | jq || echo 'Error, json fmt error';cat ${TASK_DEFINITION_TEMPLATE};exit 1
}

# Main
function main() {
    if [[ ${TRAVIS_REPO_SLUG} != "104corp/hydra" ]]; then
        exit 0
    fi

    cd ${TRAVIS_BUILD_DIR}

    install_tools
    get_sts
    set_env_var
    ecr_login
    docker_build_tag_push
    replace_var_in_taskdefinition
    ecs_register_task_definition
    ecs_update_service
    ecs_wait_services_stable
}

main
