#
# The contents of this file are subject to the terms of the Common Development and
# Distribution License (the License). You may not use this file except in compliance with the
# License.
#
# You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
# specific language governing permission and limitations under the License.
#
# When distributing Covered Software, include this CDDL Header Notice in each file and include
# the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
# Header, with the fields enclosed by brackets [] replaced by your own identifying
# information: "Portions Copyright [year] [name of copyright owner]".
#
# Copyright 2020 ForgeRock AS.
#
FROM docker.io/aaronwang0509/java-11:7.3.0

ENV FORGEROCK_HOME /home/forgerock

RUN apt-get update && \
    apt-get upgrade -y

COPY --chown=forgerock:root docker-entrypoint.sh "$FORGEROCK_HOME"/
COPY build/ "$FORGEROCK_HOME"/

USER 11111

CMD "$FORGEROCK_HOME/docker-entrypoint.sh"
