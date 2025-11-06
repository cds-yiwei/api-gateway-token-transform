IMAGE_NAME=api-gateway-token-transform-demo

.PHONY: build up down curl-discovery

build:
	docker build -t $(IMAGE_NAME) -f docker/Dockerfile .

up:
	docker run --rm -p 8080:8080 -v $(PWD):/usr/local/openresty/nginx/conf $(IMAGE_NAME)

down:
	@echo "Stop the container started with 'make up' using Ctrl-C"

curl-discovery:
	curl -v http://localhost:8080/.well-known/openid-configuration
