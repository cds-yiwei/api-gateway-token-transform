-- luacheck: globals ngx
local cjson = require "cjson.safe"

-- try to load luaossl (openssl) but be resilient: some environments provide
-- resty.openssl.* modules instead or may not have openssl available.
local openssl_ok, openssl = pcall(require, "openssl")
local pkey, digest
if openssl_ok and openssl then
    pkey = openssl.pkey
    digest = openssl.digest
end

-- fallback to resty.openssl modules when available
if not pkey then
    local ok_p, resty_pkey = pcall(require, "resty.openssl.pkey")
    if ok_p and resty_pkey then pkey = resty_pkey end
end
if not digest then
    local ok_d, resty_digest = pcall(require, "resty.openssl.digest")
    if ok_d and resty_digest then digest = resty_digest end
end
local _M = {}

local function base64url_encode(input)
    local b64 = ngx.encode_base64(input)
    b64 = b64:gsub("=+", "")
    b64 = b64:gsub("/", "_")
    b64 = b64:gsub("%+", "-")
    return b64
end

function _M.sign_rs256(a, b, c)
    -- Support two call signatures for backward compatibility:
    -- sign_rs256(payload_table, private_key_path)
    -- sign_rs256(header_table, payload_table, private_key_path)
    local header, payload_table, private_key_path
    if type(a) == "table" and type(b) == "table" and type(c) == "string" then
        header = a
        payload_table = b
        private_key_path = c
    elseif type(a) == "table" and type(b) == "string" and c == nil then
        payload_table = a
        private_key_path = b
        header = { alg = "RS256", typ = "JWT", kid = "demo_key_id" }
    else
        return nil, "invalid arguments to sign_rs256"
    end

    header = header or {}
    header.alg = "RS256"
    header.typ = header.typ or "JWT"
    if not header.kid then header.kid = "demo_key_id" end

    local header_s = base64url_encode(cjson.encode(header))
    local payload_s = base64url_encode(cjson.encode(payload_table))
    local signing_input = header_s .. "." .. payload_s

    -- read private key PEM
    local f, ferr = io.open(private_key_path, "r")
    if not f then return nil, "failed to open private key: " .. (ferr or "") end
    local pem = f:read("*a")
    f:close()

    if not pkey or type(pkey.new) ~= "function" then
        return nil, "openssl pkey module not available or incompatible"
    end

    local ok, priv = pcall(pkey.new, pem)
    -- some variants return (ok, priv) while others return priv or raise on error
    if not ok then
        -- pkey.new raised an error; try the return value stored in 'priv'
        return nil, "failed to load private key: " .. tostring(priv)
    end
    if not priv then
        return nil, "failed to load private key"
    end

    if not digest or type(digest.new) ~= "function" then
        return nil, "openssl digest module not available or incompatible"
    end

    local d = digest.new("sha256")
    if not d or type(d.update) ~= "function" then
        return nil, "failed to create digest object"
    end
    d:update(signing_input)
    local sig
    if type(priv.sign) == "function" then
        sig = priv:sign(d)
    else
        return nil, "private key object does not support sign()"
    end
    if not sig then return nil, "sign failed" end

    local sig_b64 = base64url_encode(sig)
    return signing_input .. "." .. sig_b64
end

-- Fallback HS256 signer for compatibility
function _M.sign_hs256(payload_table, key)
    local header = { alg = "HS256", typ = "JWT" }
    local header_s = base64url_encode(cjson.encode(header))
    local payload_s = base64url_encode(cjson.encode(payload_table))
    local signing_input = header_s .. "." .. payload_s
    -- Prefer lua-resty-hmac for consistent HMAC behavior across environments
    local mac, err
    do
        local ok, resty_hmac = pcall(require, "resty.hmac")
        if ok and resty_hmac then
            local algo = (resty_hmac.ALGOS and resty_hmac.ALGOS.SHA256) or resty_hmac.SHA256
            local hm, herr = resty_hmac:new(key, algo)
            if not hm then
                local succ, alt_hm = pcall(resty_hmac.new, key, algo)
                if succ and alt_hm then hm = alt_hm else herr = herr or "failed to construct resty.hmac instance" end
            end
            if hm then
                if type(hm.update) == "function" and type(hm.final) == "function" then
                    hm:update(signing_input)
                    mac = hm:final()
                elseif type(hm.digest) == "function" then
                    mac = hm:digest(signing_input, true)
                end
            end
            err = herr
        end
    end

    -- Fallback to the ngx built-in HMAC (OpenResty) if resty.hmac is not usable
    if not mac then
        if ngx and type(ngx.hmac_sha256) == "function" then
            mac = ngx.hmac_sha256(key, signing_input)
        else
            return nil, "no HMAC provider available: " .. tostring(err)
        end
    end

    local sig = base64url_encode(mac)
    return signing_input .. "." .. sig
end

return _M
