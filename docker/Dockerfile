FROM openresty/openresty:alpine-fat

LABEL maintainer="dev@example.com"

# Install build deps, luarocks and runtime packages in a single chained RUN and
# remove build deps in the same layer to avoid leaving large intermediate layers.
RUN apk add --no-cache --virtual .build-deps \
      build-base \
      openssl-dev \
      zlib-dev \
      linux-headers \
      pkgconfig \
      git \
      wget \
      luajit-dev \
    && apk add --no-cache \
      curl \
      jq \
      ca-certificates \
      openssl \
    && /usr/local/openresty/luajit/bin/luarocks --version || true \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc \
    # && /usr/local/openresty/luajit/bin/luarocks install lua-resty-http \
    && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt \
    # && /usr/local/openresty/luajit/bin/luarocks install lua-resty-hmac \
    && /usr/local/openresty/luajit/bin/luarocks install luaossl CRYPTO_DIR=/usr \
    && /usr/local/openresty/luajit/bin/luarocks install lua-cjson \
    && apk del .build-deps
# RUN apk add --no-cache --virtual .build-deps \
#       build-base \
#       openssl-dev \
#       zlib-dev \
#       linux-headers \
#       pkgconfig \
#       git \
#       wget \
#       luajit-dev \
#     && apk add --no-cache \
#       curl \
#       jq \
#       ca-certificates \
#       openssl \
#       luarocks \
#     && /usr/local/openresty/luajit/bin/luarocks --version || true \
#     && /usr/local/openresty/luajit/bin/luarocks install lua-resty-openidc \
#     && /usr/local/openresty/luajit/bin/luarocks install lua-resty-http \
#     && /usr/local/openresty/luajit/bin/luarocks install lua-resty-jwt \
#     && /usr/local/openresty/luajit/bin/luarocks install lua-cjson \
#     && apk del .build-deps

# Create a non-root user to run OpenResty
RUN addgroup -S openresty && adduser -S -G openresty openresty

# Copy project files into the OpenResty conf directory. Build from repo root:
# docker build -f docker/Dockerfile .
# Ensure you generate keys into ./keys before building. The build will COPY the
# repo-level `keys` directory into the image so keys are available in the conf.
COPY . /usr/local/openresty/nginx/conf/

WORKDIR /usr/local/openresty/nginx/conf
# RUN chmod +x /usr/local/openresty/nginx/conf/scripts/*.sh


# Ensure the non-root user owns the conf tree and create a writable keys dir
# RUN chown -R openresty:openresty /usr/local/openresty/nginx/conf \
#     && mkdir -p /usr/local/openresty/nginx/conf/keys \
#     && chown -R openresty:openresty /usr/local/openresty/nginx/conf/keys
RUN chown -R openresty:openresty /usr/local/openresty/nginx \
    && chown -R openresty:openresty /usr/local/openresty/nginx/conf \
    && chown -R openresty:openresty /usr/local/openresty/nginx/conf/keys

# Copy entrypoint that can generate demo keys at container start (runtime)
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Run as non-root user
USER openresty

EXPOSE 8080

# Entrypoint generates keys on first start if needed, then execs the CMD
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;", "-c", "/usr/local/openresty/nginx/conf/nginx.conf"]
