#!/bin/bash

echo "starting normal docker"

sudo docker compose up --remove-orphans -d

echo "starting wazuh docker"

sudo docker compose -f wazuh-docker/single-node/docker-compose.yml up