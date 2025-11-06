local _M = {}

local env_loader = require("conf.env")

-- Try loading .env from project root, then current working directory
local env, err = env_loader.load(".env")
if not env then
    -- fallback: try conf/.env
    env, err = env_loader.load("conf/.env")
end

-- Gateway config
_M.gateway = {
    base_url = env_loader.get(env, "GATEWAY_BASE_URL", "http://localhost:8080/oauth2"),
}

-- Upstream (OIDC provider) config
_M.upstream = {
    base_url = env_loader.get(env, "UPSTREAM_BASE_URL", "https://tenant.verify.com/oauth2"),
    skip_ssl_verify = env_loader.get_bool(env, "UPSTREAM_SKIP_SSL_VERIFY", true),
}

-- Salts
_M.default_salt = env_loader.get(env, "DEFAULT_SALT", "demo_default_salt")
-- CLIENT_SALTS should be a comma-separated list like "client1:salt1,client2:sal2"
local client_salts_raw = env_loader.get(env, "CLIENT_SALTS", "default_client:demo_default_salt,client_abc:demo_salt_abc")
_M.client_salts = {}
for pair in client_salts_raw:gmatch("[^,]+") do
    local k,v = pair:match("^%s*([^:]+)%s*:%s*(.+)%s*$")
    if k and v then _M.client_salts[k] = v end
end

-- Sector identifiers
_M.default_sector = env_loader.get(env, "DEFAULT_SECTOR", "example.com")
local client_sectors_raw = env_loader.get(env, "CLIENT_SECTORS", "default_client:example.com,client_abc:client-abc.example.org")
_M.client_sectors = {}
for pair in client_sectors_raw:gmatch("[^,]+") do
    local k,v = pair:match("^%s*([^:]+)%s*:%s*(.+)%s*$")
    if k and v then _M.client_sectors[k] = v end
end

-- Backchannel logout URIs
_M.default_backchannel_logout_uri = env_loader.get(env, "DEFAULT_BACKCHANNEL_LOGOUT_URI", "http://localhost:8080/logout")
local client_backchannels_raw = env_loader.get(env, "CLIENT_BACKCHANNEL_LOGOUT_URIS", "default_client:http://localhost:8080/logout")
_M.client_backchannel_logout_uris = {}
for pair in client_backchannels_raw:gmatch("[^,]+") do
    local k,v = pair:match("^%s*([^:]+)%s*:%s*(.+)%s*$")
    if k and v then _M.client_backchannel_logout_uris[k] = v end
end

-- Trim lists (comma-separated)
_M.claims_trimlist = env_loader.get_table(env, "CLAIMS_TRIMLIST", ",", { "uniqueSecurityName", "uid" })
_M.userinfo_trimlist = env_loader.get_table(env, "USERINFO_TRIMLIST", ",", { "uniqueSecurityName", "uid" })

-- Signing
_M.signing_alg = env_loader.get(env, "SIGNING_ALG", "RS256")
_M.signing_key_path = env_loader.get(env, "SIGNING_KEY_PATH", "keys/private.pem")
_M.re_sign_key = env_loader.get(env, "RE_SIGN_KEY", "demo_re_signing_key")

return _M

