-- luacheck: globals ngx
-- rest_forward.lua
-- Transparent forward proxy for /rest/* paths to upstream (no claim transformation)

local http = require "resty.http"
local cjson = require "cjson.safe"
local config = require "conf.config"
local metadata = require "lua.lib.metadata"
-- ngx.log(ngx.ERR, "rest_forward: ngx.req: ", ngx.req)
-- compute target by trimming /oauth2/ prefix and joining with upstream base
-- Use ngx.var.uri to get path without query string and preserve query string separately
-- luacheck: globals ngx
local uri = ngx.var.uri or ""
local query = ngx.var.is_args and (ngx.var.args or "") or nil
local rest_prefix = "/oauth2"

-- Ensure the request URI starts with the expected prefix
local path = ""
if uri:sub(1, #rest_prefix) == rest_prefix then
    path = uri:sub(#rest_prefix + 1)
else
    ngx.log(ngx.ERR, "rest_forward: unexpected request path '", uri, "' (expected prefix: ", rest_prefix, ")")
    return ngx.exit(400)
end

local target = config.upstream.base_url .. path
if query and query ~= "" then
    target = target .. "?" .. query
end
-- ngx.log(ngx.ERR, "rest_forward: forwarding request to upstream target: ", target)
-- Basic validation of target
if not target or target == "" or target:match("^%s*$") then
    ngx.log(ngx.ERR, "rest_forward: computed empty target URL for request: ", uri)
    return ngx.exit(502)
end

local httpc = http.new()
local headers = ngx.req.get_headers()
ngx.log(ngx.ERR, "rest_forward: incoming headers: ", cjson.encode(headers))
ngx.req.read_body()
local body = ngx.req.get_body_data()
-- ngx.log(ngx.ERR, "rest_forward: incoming body: ", body or "<empty>")

local upstream_host = config.upstream.base_url:match("^https?://([^/]+)")
if upstream_host then
    headers["host"] = upstream_host
    headers["Host"] = upstream_host
end

-- Normalize request Cookie header before sending to upstream:
-- A Cookie header from client should only contain name=value pairs separated by ';'.
-- Some clients or proxies may accidentally include attributes like Domain=...; strip any such attributes
-- so we forward a clean Cookie header to the upstream server. Also ensure cookie names/values are preserved.
local function normalize_request_cookie(cookie_header, upstream_domain)
    if not cookie_header or cookie_header == "" then
        return cookie_header
    end
    -- cookie_header may be a table (multiple Cookie headers) or a string
    local parts = {}
    if type(cookie_header) == "table" then
        for _, v in ipairs(cookie_header) do
            table.insert(parts, v)
        end
    else
        table.insert(parts, cookie_header)
    end

    local out_pairs = {}
    for _, chunk in ipairs(parts) do
        -- If upstream_domain provided, rewrite any Domain=... occurrences to upstream_domain
        if upstream_domain and upstream_domain ~= "" then
            chunk = chunk:gsub("([Dd]omain=)([^;]+)", function(pfx, _)
                return pfx .. upstream_domain
            end)
        end

        -- Split on semicolons and keep name=value pairs and Domain= attributes (so upstream receives Domain if present)
        for pair in chunk:gmatch("[^;]+") do
            local p = pair:gsub("^%s+", ""):gsub("%s+$", "")
            if p:find("=") then
                -- accept name=value and Domain=...
                if not p:match("^[Pp]ath%s*=") and not p:match("^[Ss]ecure%s*$") and not p:match("^[Hh]ttponly%s*$") and not p:match("^[Ss]amesite%s*=") and not p:match("^[Ee]xpires%s*=") then
                    table.insert(out_pairs, p)
                end
            end
        end
    end
    if #out_pairs == 0 then
        return nil
    end
    return table.concat(out_pairs, "; ")
end

-- Normalize the Cookie header to forward to upstream
if headers then
    local ck = headers["cookie"] or headers["Cookie"]
    local upstream_domain = nil
    if upstream_host and upstream_host ~= "" then
        upstream_domain = upstream_host:gsub(":(%d+)$", "")
    end
    local norm = normalize_request_cookie(ck, upstream_domain)
    if norm then
        headers["Cookie"] = norm
        headers["cookie"] = nil
    else
        -- remove cookie headers entirely if nothing remains
        headers["Cookie"] = nil
        headers["cookie"] = nil
    end
end

local opts = {
    method = ngx.req.get_method(),
    body = body,
    headers = headers,
    keepalive = false,
}
if config.upstream and config.upstream.skip_ssl_verify then
    opts.ssl_verify = false
end
if config.upstream and config.upstream.server_name then
    opts.ssl_server_name = config.upstream.server_name
end

local res, err = httpc:request_uri(target, opts)

if not res then
    ngx.log(ngx.ERR, "failed to forward rest request: ", err)
    return ngx.exit(502)
end

ngx.status = res.status
-- Copy headers, but handle Set-Cookie specially so cookies remain available to clients.
for k, v in pairs(res.headers) do
    local lk = k:lower()
    if lk ~= "content-length" and lk ~= "transfer-encoding" then
        if lk == "set-cookie" then
            -- res.headers['Set-Cookie'] may be a string or table for multiple cookies
            local cookies = {}
            if type(v) == "table" then
                cookies = v
            else
                cookies = { v }
            end
            local out_cookies = {}
            for _, cookie in ipairs(cookies) do
                -- Replace or add Domain attribute so cookie Domain is set to the gateway host (so clients receive cookies scoped to the gateway).
                -- Preserve Path, Secure, HttpOnly, SameSite, Expires, etc.
                -- Use the gateway host (ngx.var.host) as the cookie domain. Fall back to upstream_host if gateway host is unavailable.
                local cookie_domain = ""
                if ngx and ngx.var and ngx.var.host and ngx.var.host ~= "" then
                    cookie_domain = ngx.var.host
                elseif upstream_host and upstream_host ~= "" then
                    cookie_domain = upstream_host:gsub(":(%d+)$", "")
                else
                    cookie_domain = ((headers and headers["host"]) or "")
                end

                local rewritten = cookie
                -- If there's an existing Domain=... attribute (case-insensitive), replace its value
                if rewritten:find("[Dd]omain=") then
                    rewritten = rewritten:gsub("([; ]*[Dd]omain=)([^;]+)", function(pfx, _)
                        return pfx .. cookie_domain
                    end)
                else
                    -- No Domain attribute: append Domain=<cookie_domain> before any trailing attributes/semicolon.
                    -- If cookie ends with a semicolon, remove it, append Domain and re-add semicolon if needed.
                    local trailing_semicolon = rewritten:match(";[%s]*$") and ";" or ""
                    rewritten = rewritten:gsub(";[%s]*$", "") -- strip trailing semicolon(s)
                    -- Append Domain attribute
                    if cookie_domain ~= "" then
                        rewritten = rewritten .. "; Domain=" .. cookie_domain
                    end
                    -- restore trailing semicolon if originally present
                    rewritten = rewritten .. trailing_semicolon
                end

                -- Normalize spacing: remove duplicate spaces around semicolons
                rewritten = rewritten:gsub("%s*;%s*", "; ")
                rewritten = rewritten:gsub("^%s+", ""):gsub("%s+$", "")
                table.insert(out_cookies, rewritten)
            end
            -- Preserve multiple Set-Cookie headers by assigning a table
            ngx.header[k] = out_cookies
        else
            ngx.header[k] = v
        end
    end
end
-- ngx.log(ngx.ERR, "rest_forward: upstream response status: ", res.status)
-- ngx.log(ngx.ERR, "rest_forward: upstream response headers: ", cjson.encode(res.headers))
-- ngx.log(ngx.ERR, "rest_forward: upstream response body: ", res.body or "<empty>")
ngx.say(res.body)
