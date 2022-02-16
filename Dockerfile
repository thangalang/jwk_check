FROM golang:1.17-buster as build

WORKDIR /go/src/app
ADD . /go/src/app/

ENV CGO_ENABLED=0
RUN go build -o /go/bin/jwk_check

FROM alpine:3.12.7

RUN apk add curl
RUN apk add jq

LABEL com.wpengine.owner="sec-catalyst"
LABEL com.wpengine.repo="catalyst-hello-world"
LABEL com.wpengine.jira="ctlst"
LABEL com.wpengine.slack="team-pe-catalyst"

COPY --from=build /go/bin/jwk_check /
WORKDIR /
CMD ["/jwk_check"]

# # Create "guest" group/user with gid/uid 1000.
# # Guest has a home directory, but no password.
# RUN addgroup -g1000 guest && \
#     adduser -D -u1000 -Gguest guest

# USER 1000:1000