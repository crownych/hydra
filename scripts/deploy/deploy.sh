#!/bin/bash 
set -e -o pipefail

print_fun_name(){
        echo "$(tput bold;tput setaf 2 ) === ${FUNCNAME[1]} === $(tput sgr0)"
}

set_env_var() {
    print_fun_name

    # Get CFN stack outputs
    outputs=$( aws cloudformation describe-stacks | jq --arg STACKNAME ${ECS_SERVICE_STACKNAME} -r '.Stacks[] | select(.StackName==$STACKNAME)|.Outputs[]' )

    # Set ENV Variables
    # Stack.Outputs[].OutputKey==Cluster
    # Stack.Outputs[].OutputKey==ExecutionRole
    # Stack.Outputs[].OutputKey==TaskRole
    # Stack.Outputs[].OutputKey==ElasticContainerRegistry
    # Stack.Outputs[].OutputKey==LogGroup
    # Stack.Outputs[].OutputKey==TaskDefinition

    export ECS_CLUSTER=$( echo $outputs | jq -r '.| select(.OutputKey=="Cluster") | .OutputValue' )
    export TASK_DEFINITION_EXECUTION_ROLE_ARN=$( echo $outputs | jq -r '.| select(.OutputKey=="ExecutionRole") | .OutputValue' )
    export TASK_DEFINITION_TASK_ROLE_ARN=$( echo $outputs | jq -r '.| select(.OutputKey=="TaskRole") | .OutputValue' )
    export ECR_URI=$( echo $outputs | jq -r '.| select(.OutputKey=="ElasticContainerRegistry") | .OutputValue' )
    export CLW_LOG_GROUP=$( echo $outputs | jq -r '.| select(.OutputKey=="LogGroup") | .OutputValue' )
    export TASK_DEFINITION_FAMILY=$( echo $outputs | jq -r '.| select(.OutputKey=="TaskDefinition") | .OutputValue'| awk -F "/" '{print $(NF)}' | awk -F ":" '{print $1}' )
    export ECR_URI_TAG_LATEST=${ECR_URI}:latest
    export ECR_URI_TAG_CUSTOM=${ECR_URI}:${TRAVIS_COMMIT}
    
    if [[ -z ${TASK_DESIRED_COUNT} ]]; then 
        export TASK_DESIRED_COUNT_CLI="--desired-count 1"
    else 
        export TASK_DESIRED_COUNT_CLI="--desired-count "${TASK_DESIRED_COUNT}
    fi
}

ecs_register_task_definition() {
    print_fun_name
    # Register new version task definition
    aws ecs register-task-definition \
        --cli-input-json file://${TASK_DEFINITION_TEMPLATE} \
        --family ${TASK_DEFINITION_FAMILY} \
        --execution-role-arn ${TASK_DEFINITION_EXECUTION_ROLE_ARN} \
        --task-role-arn ${TASK_DEFINITION_TASK_ROLE_ARN}
}

ecs_update_service() {
    print_fun_name
    # Update service with new version task definition
    aws ecs update-service \
        --cluster ${ECS_CLUSTER} \
        --service ${ECS_SERVICE} \
        ${TASK_DESIRED_COUNT_CLI} \
        --task-definition ${TASK_DEFINITION_FAMILY}
}

install_tools() {
    print_fun_name
    pip install --user awscli jq
    export PATH=$PATH:$HOME/.local/bin
}

get_sts(){
    print_fun_name
    if [[ ${AWS_ACCESS_KEY_ID} == "" ]]; then
        echo "empty AWS_ACCESS_KEY_ID"
        exit 1
    fi
    source ${TRAVIS_BUILD_DIR}/scripts/deploy/sts.sh
}

ecr_login() {
    print_fun_name
    eval $( aws ecr get-login --no-include-email --region ${AWS_DEFAULT_REGION} )
}

docker_build_tag_push() {
    print_fun_name
    # Build, tag and push image 
    docker build -t hydra .
    docker tag hydra:latest ${ECR_URI_TAG_LATEST}
    docker tag hydra:latest ${ECR_URI_TAG_CUSTOM}
    docker push ${ECR_URI_TAG_LATEST}
    docker push ${ECR_URI_TAG_CUSTOM}
}

replace_var_in_taskdefinition(){
    print_fun_name
    # This will replace '$$ENV_VAR_NAME$$' in ${TASK_DEFINITION_TEMPLATE} with envirement variable
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
main() {
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
}

main