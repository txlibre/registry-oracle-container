FROM mhart/alpine-node:8
MAINTAINER Oraclize "tzlibre@mail.com"

COPY index.js /tmp/
ADD node_modules /tmp/node_modules/
ADD db /tmp/db/
WORKDIR /tmp/
CMD node index.js $ARG0 $ARG1 $ARG2 $ARG3