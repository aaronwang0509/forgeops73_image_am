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
# Copyright 2021-2023 ForgeRock AS.
#

# Build arg required for customer builds
ARG docker_tag=7.3.0
ARG repo=docker.io/aaronwang0509

FROM ${repo}/amster:${docker_tag} as amster

FROM ${repo}/am-empty:${docker_tag} AS generator

USER 0
RUN apt-get update -y && \
    apt-get install -y git jq unzip
USER 11111

ARG VERSION="7.0.0-SNAPSHOT"

COPY --from=amster /opt/amster /opt/amster

COPY --chown=forgerock:root scripts/* /home/forgerock/
COPY --chown=forgerock:root boot.json serverconfig.xml /opt/templates/
COPY --chown=forgerock:root amster/ /opt/amster
COPY --chown=forgerock:root build/config-placeholder.zip "$FORGEROCK_HOME"/config-placeholder.zip

RUN unzip -d "$FORGEROCK_HOME"/placeholder "$FORGEROCK_HOME"/config-placeholder.zip

WORKDIR $FORGEROCK_HOME
RUN ./install.sh

RUN ./placeholder-config.sh

WORKDIR $AM_HOME
RUN mkdir /tmp/am-home && \
    mv .homeVersion /tmp/am-home && \
    mv config /tmp/am-home && \
    rm -rf * && \
    mv /tmp/am-home/* . && \
    mkdir -p $FORGEROCK_HOME/base/config && \
    cp -r $AM_HOME/config/services $FORGEROCK_HOME/base/config && \
    mv /tmp/am-home/.homeVersion . && \
    rm -rf /tmp/am-home
RUN ls -la .
RUN git config --global user.email "ci@forgerock.com" && \
    git config --global user.name "ForgeRock" && \
    git init && \
    git add . && \
    git commit --quiet -m "Base configuration"

FROM ${repo}/am-empty:${docker_tag} AS am-base


COPY --chown=forgerock:root --from=generator $AM_HOME/.git $AM_HOME/.git
COPY --chown=forgerock:root --from=generator $AM_HOME/.homeVersion $AM_HOME/.homeVersion
COPY --chown=forgerock:root --from=generator $AM_HOME/config $AM_HOME/config
COPY --chown=forgerock:root --from=generator $FORGEROCK_HOME/base $FORGEROCK_HOME/base

COPY --chown=forgerock:root build/crypto-tool.jar "$FORGEROCK_HOME"/crypto-tool.jar
COPY --chown=forgerock:root docker-entrypoint.sh "$FORGEROCK_HOME"/
COPY --chown=forgerock:root scripts/import-pem-certs.sh "$FORGEROCK_HOME"/

RUN rm "$CATALINA_HOME"/webapps/am/WEB-INF/lib/click-extras-*.jar
RUN rm "$CATALINA_HOME"/webapps/am/WEB-INF/lib/click-nodeps-*.jar
RUN rm "$CATALINA_HOME"/webapps/am/WEB-INF/lib/velocity-*.jar

ENV FBC_BASE_PATHS=""

CMD "$FORGEROCK_HOME/docker-entrypoint.sh"
