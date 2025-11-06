-- luacheck: globals ngx
local _M = {}
local b64 = ngx.encode_base64

-- Use lua-resty-hmac as the single HMAC provider. This keeps behavior
-- consistent across environments and simplifies dependency management.
local function compute_hmac_sha256(key, data)
    if not key or not data then return nil, "missing key or data" end

    local ok, resty_hmac = pcall(require, "resty.hmac")
    if not ok or not resty_hmac then
        return nil, "lua-resty-hmac not installed"
    end

    -- Preferred constructor: resty_hmac:new(secret, algo)
    local algo = (resty_hmac.ALGOS and resty_hmac.ALGOS.SHA256) or resty_hmac.SHA256
    local hm, herr = resty_hmac:new(key, algo)
    if not hm then
        -- some variants expose constructor as resty_hmac.new
        local succ, alt_hm = pcall(resty_hmac.new, key, algo)
        if not succ or not alt_hm then
            return nil, herr or "failed to construct resty.hmac instance"
        end
        hm = alt_hm
    end

    if type(hm.update) == "function" and type(hm.final) == "function" then
        hm:update(data)
        return hm:final()
    end

    -- If resty.hmac exposes a digest method, try that
    if type(hm.digest) == "function" then
        return hm:digest(data, true)
    end

    return nil, "resty.hmac instance has no usable API"
end

local function base64url_encode(input)
    if not input then return nil end
    local b = b64(input)
    b = b:gsub("=+", "")
    b = b:gsub("/", "_")
    b = b:gsub("%+", "-")
    return b
end

function _M.compute_pairwise(sub, salt, sector)
    if not sub then return nil end
    salt = salt or "default_salt"
    -- include sector identifier to derive pairwise subject per-sector
    local input = sub
    if sector and sector ~= "" then
        input = sector .. ":" .. sub
    end
    local mac, err = compute_hmac_sha256(salt, input)
    if not mac then
        ngx.log(ngx.ERR, "compute_hmac_sha256 failed: ", err or "unknown")
        return nil
    end
    return base64url_encode(mac)
end

return _M
