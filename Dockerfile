FROM alpine:edge

RUN apk add --no-cache zig
RUN apk cache clean

ADD ./src/*.zig /oracle-source/src/
ADD ./build.zig ./build.zig.zon /oracle-source/

WORKDIR /oracle-source
RUN zig build -p /oracle

WORKDIR /oracle
RUN rm -rf /oracle-source

EXPOSE 3000

ENTRYPOINT /oracle/bin/padding_oracle