local openssl = require "openssl"
local bn = openssl.bn
local x509 = openssl.x509
local cjson = require "cjson.safe"

local _M = {}

-- Decode base64url string to raw bytes using ngx.decode_base64
local function base64url_to_bytes(s)
    if not s then return nil, "missing input" end
    -- base64url -> base64
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad == 2 then
        s = s .. "=="
    elseif pad == 3 then
        s = s .. "="
    elseif pad == 1 then
        -- invalid base64 length
        return nil, "invalid base64url length"
    end
    -- Pure-Lua base64 decode (returns raw bytes) to avoid depending on ngx or mime
    local b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    local b64inv = {}
    for i = 1, #b64chars do
        b64inv[b64chars:sub(i,i)] = i - 1
    end
    b64inv['='] = 0

    local function decode_b64(str)
        local out = {}
        for i = 1, #str, 4 do
            local a = b64inv[str:sub(i, i)] or 0
            local b = b64inv[str:sub(i+1, i+1)] or 0
            local c = b64inv[str:sub(i+2, i+2)] or 0
            local d = b64inv[str:sub(i+3, i+3)] or 0
            local n = a * 262144 + b * 4096 + c * 64 + d -- 2^18,2^12,2^6
            local byte1 = math.floor(n / 65536) % 256
            local byte2 = math.floor(n / 256) % 256
            local byte3 = n % 256
            local ch2 = str:sub(i+2, i+2)
            local ch3 = str:sub(i+3, i+3)
            if ch2 == '=' then
                table.insert(out, string.char(byte1))
            elseif ch3 == '=' then
                table.insert(out, string.char(byte1, byte2))
            else
                table.insert(out, string.char(byte1, byte2, byte3))
            end
        end
        return table.concat(out)
    end

    local decoded = decode_b64(s)
    if not decoded then return nil, "base64 decode failed" end
    return decoded, nil
end

-- Convert RSA JWK (with n/e as base64url) to PEM public key
function _M.jwk_to_pem(jwk)
    if not jwk or not jwk.n or not jwk.e then return nil, "missing n/e" end
    local n_bin, n_err = base64url_to_bytes(jwk.n)
    if not n_bin then return nil, n_err end
    local e_bin, e_err = base64url_to_bytes(jwk.e)
    if not e_bin then return nil, e_err end
    local n_bn = bn.new(n_bin, 256)
    local e_bn = bn.new(e_bin, 256)
    local rsa = openssl.rsa.new()
    rsa:set_n(n_bn)
    rsa:set_e(e_bn)
    local pem = rsa:export(true)
    return pem, nil
end

-- Verify RS256 JWT: token is 'header.payload.sig'
function _M.verify_rs256(token, pubkey_pem)
    if not token or not pubkey_pem then return false, "missing params" end
    local a, b, c = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    if not a then return false, "invalid token format" end
    local signing_input = a .. "." .. b
    local sig, s_err = base64url_to_bytes(c)
    if not sig then return false, s_err end
    -- load pkey module at runtime to avoid nil upvalue errors in some environments
    -- (some luaossl builds or embed contexts may not have openssl.pkey assigned at module load time)
    local pkey_mod = openssl.pkey
    if not pkey_mod then
        return false, "openssl.pkey module not available"
    end

    -- luaossl historically sometimes returns the key object directly or as a (ok, obj) tuple
    local k1, k2 = pkey_mod.new(pubkey_pem)
    local pub = k2 or k1
    if not pub then
        return false, "failed to load public key"
    end

    local verifier = openssl.digest.new("sha256")
    verifier:update(signing_input)
    local ok, v_err = pub:verify(verifier, sig)
    if ok == nil then
        return false, v_err or "verification error"
    end
    return ok, nil
end

return _M
