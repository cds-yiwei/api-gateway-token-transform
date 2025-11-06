-- luacheck: globals ngx
local http = require "resty.http"
local cjson = require "cjson.safe"
local ngx_shared = ngx.shared
local _M = {}

local function fetch_discovery(base_url)
    local disco_url = base_url:gsub("/$$", "") .. "/.well-known/openid-configuration"
    local httpc = http.new()
    local opts = { method = "GET" }
    -- allow upstream TLS verification config via conf.config
    local ok, conf = pcall(require, "conf.config")
    if ok and conf.upstream then
        if conf.upstream.skip_ssl_verify then opts.ssl_verify = false end
        if conf.upstream.server_name then opts.ssl_server_name = conf.upstream.server_name end
    end
    local res, err = httpc:request_uri(disco_url, opts)
    if not res then return nil, err end
    local decoded, dec_err = cjson.decode(res.body)
    if not decoded then return nil, dec_err end
    return decoded, nil
end

function _M.get(base_url)
    local dict = ngx_shared.jwks_cache
    local key = "disco:" .. base_url
    local cached = dict:get(key)
    if cached then
        local val = cjson.decode(cached)
        if val then return val end
    end
    local meta, err = fetch_discovery(base_url)
    if meta then
        dict:set(key, cjson.encode(meta), 300)
    end
    return meta, err
end

return _M
