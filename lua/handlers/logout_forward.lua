-- logout_forward.lua
-- Read incoming Logout Token (JWT), transform `sub` to pairwise-sub and forward upstream

-- luacheck: globals ngx


local http = require "resty.http"
local cjson = require "cjson.safe"
local jwt = require "resty.jwt"

local config = require "conf.config"
local pairwise = require "lua.lib.pairwise"
local metadata = require "lua.lib.metadata"
local jwt_sign = require "lua.lib.jwt_sign"

ngx.req.read_body()
local body = ngx.req.get_body_data() or ""
-- ngx.log(ngx.ERR, "logout_forward: received body: ", body)
-- incoming body might be form-encoded (logout_token=...), or JSON {"logout_token": "..."}
local logout_token
-- try form post parsing
local headers = ngx.req.get_headers()
local content_type = headers["content-type"] or headers["Content-Type"] or ""
if content_type:find("application/x-www-form-urlencoded", 1, true) then
    -- parse key=value pairs
    for k, v in body:gmatch("([^&=]+)=([^&=]+)") do
        if k == "logout_token" then
            logout_token = ngx.unescape_uri(v)
            break
        end
    end
elseif content_type:find("application/json", 1, true) then
    local ok, parsed = pcall(cjson.decode, body)
    if ok and type(parsed) == "table" and parsed.logout_token then
        logout_token = parsed.logout_token
    end
end

-- fallback: if body itself is the raw JWT, use it
if not logout_token or logout_token == "" then
    logout_token = body
end

-- ngx.log(ngx.ERR, "received logout_token: ", logout_token)

-- Decode incoming logout token; verify best-effort via JWKS if available
local decoded = jwt:load_jwt(logout_token)
if not decoded or not decoded.payload then
    ngx.log(ngx.ERR, "failed to decode logout token")
    return ngx.exit(400)
end

local payload = decoded.payload
local original_sub = payload.sub
local client_id = payload.aud or "default_client"
local salt = config.client_salts[client_id] or config.default_salt
local sector = config.client_sectors[client_id] or config.default_sector
local new_sub = pairwise.compute_pairwise(original_sub, salt, sector)

-- Trim configured claims
local trim = config.claims_trimlist or {}
for _, c in ipairs(trim) do payload[c] = nil end
payload.sub = new_sub

-- Re-sign transformed logout token using configured algorithm
local signed
if config.signing_alg == "RS256" then
    -- preserve header fields if present on incoming token (e.g., kid)
    local header = (decoded and decoded.header) or {}
    header.alg = "RS256"
    header.typ = header.typ or "JWT"
    local s, s_err = jwt_sign.sign_rs256(header, payload, config.signing_key_path)
    if not s then
        ngx.log(ngx.ERR, "failed to sign logout token: ", s_err)
        return ngx.exit(500)
    end
    signed = s
else
    signed = jwt_sign.sign_hs256(payload, config.re_sign_key or "")
end

-- Get logout endpoint from client configuration
local logout_endpoint
if config.client_backchannel_logout_uris and config.client_backchannel_logout_uris[client_id] then
    logout_endpoint = config.client_backchannel_logout_uris[client_id]
else
    logout_endpoint = config.default_backchannel_logout_uri or ""
end

local httpc = http.new()
local opts = {
    method = "POST",
    body = "logout_token=" .. signed,
    headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
    }
}
if config.upstream and config.upstream.skip_ssl_verify then opts.ssl_verify = false end
-- if config.upstream and config.upstream.server_name then opts.ssl_server_name = config.upstream.server_name end
local res, err = httpc:request_uri(logout_endpoint, opts)

if not res then
    ngx.log(ngx.ERR, "failed to forward logout: ", err)
    return ngx.exit(502)
end

ngx.status = res.status
for k, v in pairs(res.headers) do
    if k:lower() ~= "content-length" and k:lower() ~= "transfer-encoding" then
        ngx.header[k] = v
    end
end

ngx.say(res.body)
