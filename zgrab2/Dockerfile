#docker file for ZGrab2
FROM golang:1.24-bookworm AS build

RUN go install github.com/zmap/zgrab2/cmd/zgrab2@latest

FROM debian:bookworm-slim
COPY --from=build /go/bin/zgrab2 /usr/local/bin/zgrab2

ENTRYPOINT ["zgrab2"]