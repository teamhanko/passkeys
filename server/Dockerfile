# Build the passkey-server binary
FROM --platform=$BUILDPLATFORM golang:1.24 AS builder

ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY audit_log audit_log
COPY api api
COPY build_info build_info
COPY commands commands
COPY config config
COPY crypto crypto
COPY persistence persistence
COPY mapper mapper
COPY utils utils

# Build
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH="$TARGETARCH" go build -a -o passkey-server main.go

# Use distroless as minimal base image to package passkey-server binary
# See https://github.com/GoogleContainerTools/distroless for details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/passkey-server .
USER 65532:65532

ENTRYPOINT ["/passkey-server"]
