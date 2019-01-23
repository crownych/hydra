#!/bin/bash 
-e -o pipefail

# Vaiables
export ECS_CLUSTER="Cluster-${ECS_SERVICE}"
export TASK_DEFINITION_TEMPLATE="${TRAVIS_BUILD_DIR}/scripts/deploy/task-definition.json"
export TASK_DEFINITION_FAMILY="${ECS_SERVICE}-TaskDefinition"
export TASK_DEFINITION_EXECUTION_ROLE_ARN="${ECS_SERVICE}-ExecutionRole"
export TASK_DEFINITION_TASK_ROLE_ARN="${ECS_SERVICE}-TaskRole"
export ECR_URI="${AWS_ACCOUNTID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com/${ECS_SERVICE}"
export ECR_URI_TAG_LATEST=${ECR_URI}:latest
export ECR_URI_TAG_CUSTOM=${ECR_URI}:${TRAVIS_COMMIT}
export CLW_LOG_GROUP="/ecs/${TASK_DEFINITION_FAMILY}"

if [[ ${TRAVIS_REPO_SLUG} != "104corp/hydra" ]]; then
    exit 0
fi

if [[ ${AWS_ACCESS_KEY_ID} == "" ]]; then
    echo "empty AWS_ACCESS_KEY_ID"
    exit 1
fi

# Install AWS cli
pip install --user awscli jq
export PATH=$PATH:$HOME/.local/bin

# Handle sts
source ${TRAVIS_BUILD_DIR}/scripts/deploy/sts.sh

# ECR login
eval $(aws ecr get-login --no-include-email --region ${AWS_DEFAULT_REGION})

# Go build home
cd ${TRAVIS_BUILD_DIR}

# Build, tag and push image 
docker build -t hydra .
docker tag hydra:latest ${ECR_URI_TAG_LATEST}
docker tag hydra:latest ${ECR_URI_TAG_CUSTOM}
docker push ${ECR_URI_TAG_LATEST}
docker push ${ECR_URI_TAG_CUSTOM}

# This will replace '$$ENV_VAR_NAME$$' in ${TASK_DEFINITION_TEMPLATE} with envirement variable
# Example
# $$ECR_URI_TAG_CUSTOM$$ : Image with commit sha
# $$CLW_LOG_GROUP$$ : log group

str=`cat ${TASK_DEFINITION_TEMPLATE}`
while [[ $str =~ ('$$'([[:alnum:]_]+)'$$') ]]; do
    str=${str//${BASH_REMATCH[1]}/${!BASH_REMATCH[2]}}
done
echo "$str" | jq > ${TASK_DEFINITION_TEMPLATE}

# Register new version task definition
aws ecs register-task-definition \
    --cli-input-json file://${TASK_DEFINITION_TEMPLATE} \
	--family ${TASK_DEFINITION_FAMILY} \
	--execution-role-arn ${TASK_DEFINITION_EXECUTION_ROLE_ARN} \
	--task-role-arn ${TASK_DEFINITION_TASK_ROLE_ARN}

# Update service with new version task definition
aws ecs update-service \
    --cluster ${ECS_CLUSTER} \
    --service ${ECS_SERVICE} \
    --task-definition ${TASK_DEFINITION_FAMILY}