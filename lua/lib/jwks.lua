-- luacheck: globals ngx
local http = require "resty.http"
local cjson = require "cjson.safe"
local ngx_shared = ngx.shared
local _M = {}

local function fetch_jwks(jwks_uri)
    local httpc = http.new()
    local opts = { method = "GET" }
    local ok, conf = pcall(require, "conf.config")
    if ok and conf.upstream then
        if conf.upstream.skip_ssl_verify then opts.ssl_verify = false end
        if conf.upstream.server_name then opts.ssl_server_name = conf.upstream.server_name end
    end
    local res, err = httpc:request_uri(jwks_uri, opts)
    if not res then return nil, err end
    local decoded, dec_err = cjson.decode(res.body)
    if not decoded then return nil, dec_err end
    return decoded, nil
end

function _M.get(jwks_uri)
    local dict = ngx_shared.jwks_cache
    local key = "jwks:" .. jwks_uri
    local cached = dict:get(key)
    if cached then
        local val = cjson.decode(cached)
        if val then return val end
    end
    local jwks, err = fetch_jwks(jwks_uri)
    if jwks then
        dict:set(key, cjson.encode(jwks), 300)
    end
    return jwks, err
end

-- find key by kid
function _M.find_key(jwks, kid)
    if not jwks or not jwks.keys then return nil end
    for _, k in ipairs(jwks.keys) do
        if k.kid == kid then return k end
    end
    return nil
end

-- convert jwk to PEM (prefer x5c chain if available)
function _M.jwk_to_pem(jwk)
    if not jwk then return nil end
    if jwk.x5c and jwk.x5c[1] then
        -- x5c is base64 DER cert
        local der_b64 = jwk.x5c[1]
        local der = ngx.decode_base64(der_b64)
        if not der then return nil end
        -- wrap DER in PEM
        local pem = "-----BEGIN CERTIFICATE-----\n" .. der_b64 .. "\n-----END CERTIFICATE-----\n"
        return pem
    end
    -- fallback to n/e conversion (handled in jws_verify module)
    return nil
end

return _M
