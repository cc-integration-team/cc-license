# Build the application from source
FROM golang:1.26-alpine AS build-stage

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/cc-license .

# Run the tests in the container
FROM build-stage AS run-test-stage
RUN go test -v ./...

# Deploy the application binary into a lean image
FROM alpine:3.21 AS build-release-stage

WORKDIR /app

COPY --from=run-test-stage /app/cc-license /app/cc-license

EXPOSE 8080

# USER nonroot:nonroot

ENTRYPOINT [ "/app/cc-license" ]