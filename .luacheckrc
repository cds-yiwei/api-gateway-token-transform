-- Luacheck configuration to allow OpenResty/Nginx global `ngx`
-- See https://luacheck.readthedocs.io

std = "lua52"
read_globals = {
  "ngx",
}
