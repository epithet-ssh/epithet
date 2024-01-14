# syntax=docker/dockerfile:1

# Build the application from source
FROM golang:1.21-bookworm AS build
WORKDIR /go/src/app
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /go/bin/epithet-ca ./cmd/epithet-ca 

# Deploy the application binary into a lean image
FROM gcr.io/distroless/base-debian12 AS build-release-stage
WORKDIR /
COPY --from=build /go/bin/epithet-ca /epithet-ca
USER nonroot:nonroot

ENTRYPOINT ["/epithet-ca"]
