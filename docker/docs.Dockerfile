FROM asciidoctor/docker-asciidoctor:1.62.0
LABEL maintainer=dadrus@gmx.de

# install html5s backend
RUN gem install asciidoctor-html5s

# setup hugo
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community hugo

# setup node
RUN apk add --no-cache npm

COPY scripts/run-docs.sh /run-docs.sh

WORKDIR /opt/heimdall/docs

#USER 10111

CMD ["/run-docs.sh"]