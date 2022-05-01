FROM jekyll/jekyll:4.2.2

RUN apk add --no-cache graphviz plantuml
RUN plantuml -testdot
RUN gem install just-the-docs --version "0.3.3" --source "https://rubygems.pkg.github.com/just-the-docs"
RUN gem install webrick


