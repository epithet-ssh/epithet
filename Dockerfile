# syntax=docker/dockerfile:1

# Build the application from source
FROM golang:1.21-bookworm AS build-stage
WORKDIR /app
ADD ./ ./
RUN go mod download
RUN go build -o /epithet-ca ./cmd/epithet-ca 

# Deploy the application binary into a lean image
FROM gcr.io/distroless/base-debian12 AS build-release-stage
WORKDIR /
COPY --from=build-stage /epithet-ca /epithet-ca
USER nonroot:nonroot

ENTRYPOINT ["/epithet-ca", "-k", "/ca.key"]
