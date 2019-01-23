#!/bin/bash 
-e -o pipefail

set_env_var() {
    # Vaiables
    export ECS_CLUSTER="Cluster-${ECS_SERVICE}"
    export TASK_DEFINITION_FAMILY="${ECS_SERVICE}-TaskDefinition"
    export TASK_DEFINITION_EXECUTION_ROLE_ARN="${ECS_SERVICE}-ExecutionRole"
    export TASK_DEFINITION_TASK_ROLE_ARN="${ECS_SERVICE}-TaskRole"
    export ECR_URI="${AWS_ACCOUNTID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${ECS_SERVICE}"
    export ECR_URI_TAG_LATEST=${ECR_URI}:latest
    export ECR_URI_TAG_CUSTOM=${ECR_URI}:${TRAVIS_COMMIT}
    export CLW_LOG_GROUP="/ecs/${TASK_DEFINITION_FAMILY}"
    if [[ -z ${TASK_DESIRED_COUNT} ]]; then 
        export TASK_DESIRED_COUNT_CLI="--desired-count 1"
    else 
        export TASK_DESIRED_COUNT_CLI="--desired-count "${TASK_DESIRED_COUNT}
    fi
}

ecs_register_task_definition() {
    # Register new version task definition
    aws ecs register-task-definition \
        --cli-input-json file://${TASK_DEFINITION_TEMPLATE} \
        --family ${TASK_DEFINITION_FAMILY} \
        --execution-role-arn ${TASK_DEFINITION_EXECUTION_ROLE_ARN} \
        --task-role-arn ${TASK_DEFINITION_TASK_ROLE_ARN}
}

ecs_update_service() {
    # Update service with new version task definition
    aws ecs update-service \
        --cluster ${ECS_CLUSTER} \
        --service ${ECS_SERVICE} \
        ${TASK_DESIRED_COUNT_CLI} \
        --task-definition ${TASK_DEFINITION_FAMILY}
}

install_tools() {
    pip install --user awscli jq
    export PATH=$PATH:$HOME/.local/bin
}

get_sts(){
    if [[ ${AWS_ACCESS_KEY_ID} == "" ]]; then
        echo "empty AWS_ACCESS_KEY_ID"
        exit 1
    fi
    source ${TRAVIS_BUILD_DIR}/scripts/deploy/sts.sh
}

ecr_login() {
    eval $(aws ecr get-login --no-include-email --region ${AWS_DEFAULT_REGION})
}

docker_build_tag_push() {
    # Build, tag and push image 
    docker build -t hydra .
    docker tag hydra:latest ${ECR_URI_TAG_LATEST}
    docker tag hydra:latest ${ECR_URI_TAG_CUSTOM}
    docker push ${ECR_URI_TAG_LATEST}
    docker push ${ECR_URI_TAG_CUSTOM}
}

replace_var_in_taskdefinition(){
    # This will replace '$$ENV_VAR_NAME$$' in ${TASK_DEFINITION_TEMPLATE} with envirement variable
    # Example
    # $$ECR_URI_TAG_CUSTOM$$ : Image with commit sha
    # $$CLW_LOG_GROUP$$ : log group

    str=`cat ${TASK_DEFINITION_TEMPLATE}`
    while [[ $str =~ ('$$'([[:alnum:]_]+)'$$') ]]; do
        str=${str//${BASH_REMATCH[1]}/${!BASH_REMATCH[2]}}
    done
    echo "$str" | jq > ${TASK_DEFINITION_TEMPLATE}    
}

# Main
main() {
    if [[ ${TRAVIS_REPO_SLUG} != "104corp/hydra" ]]; then
        exit 0
    fi

    cd ${TRAVIS_BUILD_DIR}

    install_tools
    set_env_var
    get_sts
    ecr_login
    docker_build_tag_push
    replace_var_in_taskdefinition
    ecs_register_task_definition
    ecs_update_service
}

main