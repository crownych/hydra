#!/bin/bash -e -o pipefail

if [[ ${TRAVIS_REPO_SLUG} != "104corp/hydra" ]]; then
    exit 0
fi

if [[ ${AWS_ACCESS_KEY_ID} == "" ]]; then
    echo "empty AWS_ACCESS_KEY_ID"
    exit 1
fi

pip install --user awscli
export PATH=$PATH:$HOME/.local/bin

source ${TRAVIS_BUILD_DIR}/scripts/sts.sh
eval $(aws ecr get-login --no-include-email --region ${AWS_DEFAULT_REGION})

cd ${TRAVIS_BUILD_DIR}

docker build -t hydra .
docker tag hydra:latest ${AUTH_REPO_URI}:latest
docker push ${AUTH_REPO_URI}:latest
docker tag hydra:latest ${AUTH_REPO_URI}:${TRAVIS_COMMIT}
docker push ${AUTH_REPO_URI}:${TRAVIS_COMMIT}
