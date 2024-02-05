#!/bin/bash

#
# Copyright 2019-2023 ForgeRock AS. All Rights Reserved
#

. $FORGEROCK_HOME/debug.sh
. $FORGEROCK_HOME/profiling.sh

CATALINA_OPTS="$CATALINA_OPTS $AM_CONTAINER_JVM_ARGS $CATALINA_USER_OPTS $JFR_OPTS"

echo "This is a base image used to build other images; it should not be used for any other purpose"
echo "Please refer to the ForgeOps documentation at https://github.com/ForgeRock/forgeops"
exit 1
