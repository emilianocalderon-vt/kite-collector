FROM golang:1.26-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /kite-collector ./cmd/kite-collector

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /kite-collector /kite-collector
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/kite-collector"]
CMD ["agent", "--stream"]
