local _M = {}

-- Simple .env file parser
-- Supports lines like KEY=VALUE, ignoring comments (#) and blank lines.
-- Values are returned as strings. Provide helpers for booleans and tables.

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function parse_line(line)
    -- remove surrounding whitespace
    line = trim(line)
    if line == "" then return nil end
    if line:sub(1,1) == "#" then return nil end

    local key, val = line:match('^([%w_%-%:]+)%s*=%s*(.*)$')
    if not key then return nil end

    -- remove surrounding quotes for value
    if val:sub(1,1) == '"' and val:sub(-1,-1) == '"' then
        val = val:sub(2, -2)
    elseif val:sub(1,1) == "'" and val:sub(-1,-1) == "'" then
        val = val:sub(2, -2)
    end
    val = trim(val)
    return key, val
end

function _M.load(path)
    path = path or ".env"
    local file, err = io.open(path, "r")
    if not file then
        return {}, err
    end
    local env = {}
    for line in file:lines() do
        local k,v = parse_line(line)
        if k then env[k] = v end
    end
    file:close()
    return env, nil
end

function _M.get(env, key, default)
    if not env then return default end
    local v = env[key]
    if v == nil or v == "" then return default end
    return v
end

function _M.get_bool(env, key, default)
    local v = _M.get(env, key, nil)
    if v == nil then return default end
    v = v:lower()
    if v == "1" or v == "true" or v == "yes" then return true end
    if v == "0" or v == "false" or v == "no" then return false end
    return default
end

function _M.get_table(env, key, sep, default)
    local v = _M.get(env, key, nil)
    if v == nil then return default end
    sep = sep or ","
    local out = {}
    for item in v:gmatch("[^"..sep.."]+") do
        item = trim(item)
        if item ~= "" then table.insert(out, item) end
    end
    return out
end

return _M
