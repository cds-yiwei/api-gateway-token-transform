-- userinfo_proxy.lua
-- Reverse proxy to upstream userinfo endpoint: transform `sub` to pairwise-sub and trim claims

-- luacheck: globals ngx

local http = require "resty.http"
local cjson = require "cjson.safe"
local config = require "conf.config"
local pairwise = require "lua.lib.pairwise"
local metadata = require "lua.lib.metadata"

local in_headers = ngx.req.get_headers()
local forward_headers = {}
if in_headers.Authorization then forward_headers["Authorization"] = in_headers.Authorization end

local upstream_meta, m_err = metadata.get(config.upstream.base_url)
local userinfo_endpoint = config.upstream.base_url .. "/oauth2/v1/userinfo"
if upstream_meta and upstream_meta.userinfo_endpoint then userinfo_endpoint = upstream_meta.userinfo_endpoint end

local httpc = http.new()
local opts = { method = "GET", headers = forward_headers }
if config.upstream and config.upstream.skip_ssl_verify then opts.ssl_verify = false end
if config.upstream and config.upstream.server_name then opts.ssl_server_name = config.upstream.server_name end
local res, err = httpc:request_uri(userinfo_endpoint, opts)
if not res then
    ngx.log(ngx.ERR, "failed fetching upstream userinfo: ", err)
    return ngx.exit(502)
end

local json, dec_err = cjson.decode(res.body)
if not json then
    ngx.log(ngx.ERR, "invalid JSON from upstream userinfo: ", dec_err)
    ngx.status = res.status
    ngx.say(res.body)
    return ngx.exit(res.status)
end

local original_sub = json.sub
local client_id = in_headers["x-client-id"] or json.aud or "default_client"
local salt = config.client_salts[client_id] or config.default_salt
local sector = config.client_sectors[client_id] or config.default_sector
local new_sub = pairwise.compute_pairwise(original_sub, salt, sector)

-- Trim claims listed in userinfo_trimlist
local trim = config.userinfo_trimlist or {}
for _, c in ipairs(trim) do json[c] = nil end
json.sub = new_sub

ngx.status = res.status
for k, v in pairs(res.headers) do
    if k:lower() ~= "content-length" and k:lower() ~= "transfer-encoding" then
        ngx.header[k] = v
    end
end

ngx.say(cjson.encode(json))
