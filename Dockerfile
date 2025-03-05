FROM golang:1.23 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
COPY cmd/ cmd/
COPY api/ api/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a \
    -o app main.go

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /workspace/app /usr/local/bin/app
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["app"]
CMD ["runserver", "--host=0.0.0.0", "--port=8080"]
