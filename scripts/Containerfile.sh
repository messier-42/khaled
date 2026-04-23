#!/usr/bin/env bash
## This script generates a Containerfile to build an OCI image containing the
## specified program.
set -eo pipefail

## Parse arguments.
APP_NAME="$1"
if [[ -z "$APP_NAME" ]]; then
  echo "usage: $0 {khaled}"
  exit 2
fi

case "$APP_NAME" in
  khaled)
    APP_TITLE="$APP_NAME"
    ;;
esac

## Use our PQ Go compiler image to build.
echo 'FROM oci.messier42.com/go:1.25.9-pq1 AS builder'

echo 'RUN apk add --no-cache ca-certificates git'
echo 'ARG TARGETOS'
echo 'ARG TARGETARCH'

echo 'WORKDIR /work'
echo 'COPY --from=cabe-go . ./cabe-go/'
echo 'WORKDIR /work/khaled'
echo 'ENV GOCACHE=/go/pkg/.go-build/'

## If we are releasing, copy in VCS metadata so `go build` detects it and implants
## a version stamp readable via `go version -m`. In development, skip this.
[[ -n "$TARGET_VERSION" ]] && echo "COPY ./.git ./.git" # for `go version` metadata

if [[ "$APP_NAME" == khaled ]]; then
  echo "COPY ./go.mod ./go.sum ."
  echo "COPY ./cmd ./cmd"
  echo "COPY ./pkg ./pkg"
fi

## Do a full rebuild for release builds.
_xbcmd=; [[ -n "$TARGET_VERSION" ]] && _xbcmd=-a

binaries=()
do_build() {
  binaries+=("$1")
  echo "RUN CGO_ENABLED=0 GOOS=\${TARGETOS:-linux} GOARCH=\${TARGETARCH} go build $_xbcmd -trimpath -o /$1 $2"
}
do_build "$APP_NAME" ./cmd/khaled

## Use a separate distroless image to minimise image size and remove unnecessary cruft using build.
echo 'FROM gcr.io/distroless/static-debian12:nonroot'

## Add image metadata.
echo "LABEL org.opencontainers.image.title=\"$APP_TITLE\""
[[ -n "$TARGET_VERSION" ]] && echo "LABEL org.opencontainers.image.version=\"$TARGET_VERSION\""
echo 'LABEL org.opencontainers.image.vendor="messier42.com"'

for x in "${binaries[@]}"; do
  echo "COPY --from=builder /$x /"
done
echo 'USER 65532:65532' ## Non-root operation.

## Expose ports.
[[ "$APP_NAME" == khaled ]] && echo 'EXPOSE 8443'

## Entrypoint.
echo 'ENTRYPOINT ["/'$APP_NAME'"]'

exit 0
