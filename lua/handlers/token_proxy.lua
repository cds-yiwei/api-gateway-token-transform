-- luacheck: globals ngx
-- token_proxy.lua
-- Proxy to upstream token endpoint, transform id_token sub -> pairwise-sub and trim claims

local http = require "resty.http"
local cjson = require "cjson.safe"
local jwt = require "resty.jwt"

local config = require "conf.config"
local pairwise = require "lua.lib.pairwise"
local metadata = require "lua.lib.metadata"
local jwks = require "lua.lib.jwks"
local jwt_sign = require "lua.lib.jwt_sign"

-- ngx.log(ngx.INFO, "calling token endpoint via Gateway")
-- Attempt to verify using JWKS discovered from upstream metadata
local upstream_meta, m_err = metadata.get(config.upstream.base_url)

local function read_body()
    ngx.req.read_body()
    return ngx.req.get_body_data()
end

local function forward_to_upstream(method, body, headers)
    local httpc = http.new()
    local opts = {
        method = method,
        body = body,
        headers = headers,
    }

    -- Allow skipping TLS verification for testing via config.upstream.skip_ssl_verify
    -- Prefer providing a proper CA bundle in production instead of disabling verification.
    if config.upstream and config.upstream.skip_ssl_verify then
        ngx.log(ngx.WARN, "upstream TLS verification is disabled by configuration")
        opts.ssl_verify = false
    end

    -- Optional SNI override if needed
    if config.upstream and config.upstream.server_name then
        opts.ssl_server_name = config.upstream.server_name
    end

    local res, err = httpc:request_uri(upstream_meta.token_endpoint, opts)
    if not res then return nil, err end
    return res, nil
end

local body = read_body()
local headers = ngx.req.get_headers()
local upstream_host = config.upstream.base_url:match("^https?://([^/]+)")
if upstream_host then
    headers["host"] = upstream_host
    headers["Host"] = upstream_host
end
local method = ngx.req.get_method()

local res, err = forward_to_upstream(method, body, headers)
if not res then
    ngx.log(ngx.ERR, "upstream token request failed: ", err)
    return ngx.exit(502)
end
-- ngx.log(ngx.ERR, "Token endpoint response body: ", res.body)
local resp_json, decode_err = cjson.decode(res.body)
if not resp_json then
    ngx.log(ngx.ERR, "invalid JSON from upstream token endpoint: ", decode_err)
    ngx.status = res.status
    ngx.say(res.body)
    return ngx.exit(res.status)
end

if resp_json.id_token then
    local verified = false
    local decoded = jwt:load_jwt(resp_json.id_token)
    if decoded and decoded.header and upstream_meta and upstream_meta.jwks_uri then
            -- fetch jwks via module (module may cache). jwks.get currently does its own http call.
            local jwks_obj, j_err = jwks.get(upstream_meta.jwks_uri)
        if jwks_obj and decoded.header.kid then
            local key = jwks.find_key(jwks_obj, decoded.header.kid)
            if key and key.kty == "oct" and key.k then
                -- HMAC symmetric key present in jwks (k) -> verify
                local ok = jwt:verify_jwt_obj({ secret = key.k }, resp_json.id_token)
                if ok and ok.verified then verified = true end
            else
                -- Try RSA verification via jwk -> PEM and luaossl
                local jws_verify = require "lua.lib.jws_verify"
                local pem = jwks.jwk_to_pem(key)
                if not pem and key.n and key.e then
                    -- convert n/e to PEM using jws_verify helper
                    local pem_conv, conv_err = jws_verify.jwk_to_pem(key)
                    pem = pem_conv
                end
                if pem then
                    local ok, v_err = jws_verify.verify_rs256(resp_json.id_token, pem)
                    if ok then verified = true end
                end
            end
        end
    end

    if not verified then
        -- best-effort: load without verification but continue transformation
        if not decoded or not decoded.payload then
            ngx.log(ngx.ERR, "failed to decode id_token")
            return ngx.exit(400)
        end
    end

    local payload = decoded.payload
    local header = decoded.header
    local original_sub = payload.sub
    local client_id = (payload.aud and (type(payload.aud) == "table" and payload.aud[1] or payload.aud)) or "default_client"
    local salt = config.client_salts[client_id] or config.default_salt
    local sector = config.client_sectors[client_id] or config.default_sector
    local new_sub = pairwise.compute_pairwise(original_sub, salt, sector)

    -- Trim claims listed in trimlist (remove them)
    local trim = config.claims_trimlist or {}
    for _, c in ipairs(trim) do payload[c] = nil end
    payload.sub = new_sub

    -- Replace payload.iss if upstream metadata issuer differs from gateway config
    -- payload.iss = config.gateway.base_url
    

    -- Re-sign transformed payload using configured signing algorithm
    if config.signing_alg == "RS256" then
        header.alg = "RS256"
        header.typ = header.typ or "JWT"
        local signed, s_err = jwt_sign.sign_rs256(header, payload, config.signing_key_path)
        if not signed then
            ngx.log(ngx.ERR, "failed to sign transformed token: ", s_err)
            return ngx.exit(500)
        end
        resp_json.id_token = signed
    else
        resp_json.id_token = jwt_sign.sign_hs256(payload, config.re_sign_key or "")
    end
end

ngx.status = res.status
for k, v in pairs(res.headers) do
    if k:lower() ~= "content-length" and k:lower() ~= "transfer-encoding" then
        ngx.header[k] = v
    end
end

ngx.say(cjson.encode(resp_json))
