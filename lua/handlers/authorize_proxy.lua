-- luacheck: globals ngx
-- authorize_proxy.lua
-- Fetch upstream authorization JSON, replace upstream tenant URLs with gateway host

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
    return ngx.re.gsub(body, upstream_base, gateway_base, "ijo")
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

local fetch_url = meta.authorization_endpoint
-- fetch_url should add any query parameters from the original request
local args = ngx.var.is_args and (ngx.var.args or "") or nil
if args and args ~= "" then
    fetch_url = fetch_url .. "?" .. args
end
-- ngx.log(ngx.ERR, "upstream authorization: ", fetch_url)
local res, err = fetch_upstream(fetch_url)
if not res then
    ngx.log(ngx.ERR, "failed fetching upstream authorization: ", err)
    return ngx.exit(502)
end

local modified = replace_urls(res.body, config.upstream.base_url, gateway_base)
if not modified then
    ngx.log(ngx.ERR, "failed to modify authorization body")
    return ngx.exit(500)
end
-- ngx.log(ngx.ERR, "res.body: ", res.body)
-- -- Also need to replace location header if present
-- if res.headers["Location"] then
--     local new_location = ngx.re.gsub(res.headers["Location"], config.upstream.base_url, gateway_base, "ijo")
--     if new_location then
--         res.headers["Location"] = new_location
--     end
-- end

-- -- Also need to replace response.headers that may contain URLs
-- ngx.log(ngx.ERR, "modified authorization response headers: ", cjson.encode(res.headers))

ngx.status = res.status
for k, v in pairs(res.headers) do
    if k:lower() ~= "content-length" and k:lower() ~= "transfer-encoding" then
        ngx.header[k] = v
    end
end

ngx.say(modified)
