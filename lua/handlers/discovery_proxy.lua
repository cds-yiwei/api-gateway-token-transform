-- discovery_proxy.lua
-- Fetch upstream discovery JSON, replace upstream tenant URLs with gateway host

-- luacheck: globals ngx

local http = require "resty.http"
local cjson = require "cjson.safe"


local config = require "conf.config"
local metadata = require "lua.lib.metadata"

local function fetch_upstream(url)
    local httpc = http.new()
    local opts = { method = "GET" }
    if config.upstream and config.upstream.skip_ssl_verify then
        opts.ssl_verify = false
    end
    if config.upstream and config.upstream.server_name then
        opts.ssl_server_name = config.upstream.server_name
    end
    local res, err = httpc:request_uri(url, opts)
    if not res then return nil, err end
    return res, nil
end

local function replace_urls(body, upstream_base, gateway_base)
    if not body then return nil end
    -- simple global replace; for more robust handling parse JSON and update fields
    local json = cjson.decode(body)
    if not json then return nil end
    json.authorization_endpoint = ngx.re.gsub(json.authorization_endpoint, upstream_base, gateway_base, "ijo")
    json.token_endpoint = ngx.re.gsub(json.token_endpoint, upstream_base, gateway_base, "ijo")
    json.userinfo_endpoint = ngx.re.gsub(json.userinfo_endpoint, upstream_base, gateway_base, "ijo")
    json.jwks_uri = ngx.re.gsub(json.jwks_uri, upstream_base, gateway_base, "ijo")
    -- json.end_session_endpoint = ngx.re.gsub(json.end_session_endpoint, upstream_base, gateway_base, "ijo")
    -- json.introspection_endpoint = ngx.re.gsub(json.introspection_endpoint, upstream_base, gateway_base, "ijo")
    -- json.revocation_endpoint = ngx.re.gsub(json.revocation_endpoint, upstream_base, gateway_base, "ijo")
    -- json.device_authorization_endpoint = ngx.re.gsub(json.device_authorization_endpoint, upstream_base, gateway_base, "ijo")
    -- json.registration_endpoint = ngx.re.gsub(json.registration_endpoint, upstream_base, gateway_base, "ijo")
    -- json.pushed_authorization_request_endpoint = ngx.re.gsub(json.pushed_authorization_request_endpoint, upstream_base, gateway_base, "ijo")
    -- json.user_authorization_endpoint = ngx.re.gsub(json.user_authorization_endpoint, upstream_base, gateway_base, "ijo")
    -- json.device_authorization_endpoint = ngx.re.gsub(json.device_authorization_endpoint, upstream_base, gateway_base, "ijo")
    return cjson.encode(json)
end

-- prefer metadata discovery if available
local upstream_base = config.upstream.base_url
local upstream_discovery = config.upstream.discovery
local gateway_base = config.gateway.base_url

local meta = nil
if upstream_base then
    meta = metadata.get(upstream_base)
    if meta and meta.issuer and not upstream_discovery then
        upstream_discovery = upstream_base:gsub("/+$", "") .. "/.well-known/openid-configuration"
    end
end

local res, err = fetch_upstream(upstream_discovery)
if not res then
    ngx.log(ngx.ERR, "failed fetching upstream discovery: ", err)
    return ngx.exit(502)
end

local modified = replace_urls(res.body, config.upstream.base_url, gateway_base)
if not modified then
    ngx.log(ngx.ERR, "failed to modify discovery body")
    return ngx.exit(500)
end

ngx.status = res.status
for k, v in pairs(res.headers) do
    if k:lower() ~= "content-length" and k:lower() ~= "transfer-encoding" then
        ngx.header[k] = v
    end
end

ngx.say(modified)
