-- External scanners. Each one turns a buffer into a list of secret strings; the plugin then masks
-- every occurrence of those strings, so masks survive edits made before the next scan finishes.
local M = {}

local running = {} -- "name:bufnr" -> vim.SystemObj

local function buf_lines(buf)
  return vim.api.nvim_buf_get_lines(buf, 0, -1, false)
end

---@class secrets.Scanner
---@field cmd string default executable
---@field prepare fun(buf: integer, cmd: string): string[], string?, fun()? argv, stdin, cleanup
---@field parse fun(stdout: string, argv: string[]): string[]

---@type table<string, secrets.Scanner>
M.defs = {
  -- ripsecrets only reads regular files (a stdin pipe is silently skipped), so scan a copy in
  -- Neovim's private temp dir and delete it as soon as the scan ends.
  ripsecrets = {
    cmd = "ripsecrets",
    prepare = function(buf, cmd)
      local ext = vim.fs.basename(vim.api.nvim_buf_get_name(buf)):match("%.[^.]+$") or ""
      local path = vim.fn.tempname() .. ext
      assert(vim.fn.writefile(buf_lines(buf), path) == 0, "could not write temp file")
      return { cmd, "--only-matching", path }, nil, function()
        os.remove(path)
      end
    end,
    parse = function(stdout, argv)
      local prefix = argv[#argv] .. ":"
      local secrets = {}
      for line in stdout:gmatch("[^\n]+") do
        local secret = line:sub(1, #prefix) == prefix and line:match("^%d+:(.+)$", #prefix + 1)
        if secret then
          table.insert(secrets, secret)
        end
      end
      return secrets
    end,
  },
  -- Detection only: --validate would send candidate credentials to the provider, so it is never passed.
  betterleaks = {
    cmd = "betterleaks",
    prepare = function(buf, cmd)
      return { cmd, "stdin", "--no-banner", "--no-color", "-l", "error", "-f", "json", "-r", "-" },
        table.concat(buf_lines(buf), "\n") .. "\n"
    end,
    parse = function(stdout)
      local ok, findings = pcall(vim.json.decode, stdout)
      local secrets = {}
      for _, f in ipairs(ok and type(findings) == "table" and findings or {}) do
        if type(f.Secret) == "string" and f.Secret ~= "" then
          table.insert(secrets, f.Secret)
        end
      end
      return secrets
    end,
  },
}

---@param name string
---@param buf integer
---@param cmd string
---@param cb fun(secrets: string[])
---@return boolean started
function M.scan(name, buf, cmd, cb)
  local def, key = M.defs[name], name .. ":" .. buf
  M.stop(name, buf)
  local ok, argv, stdin, cleanup = pcall(def.prepare, buf, cmd)
  if not ok then
    return false
  end
  local function finish()
    if cleanup then
      cleanup()
    end
  end
  local obj -- declared first so the callback sees the handle
  local started
  started, obj = pcall(vim.system, argv, { stdin = stdin, text = true }, function(res)
    finish()
    vim.schedule(function()
      if running[key] ~= obj then
        return -- superseded by a newer scan
      end
      running[key] = nil
      if res.signal == 0 then
        cb(vim.fn.uniq(vim.fn.sort(def.parse(res.stdout or "", argv))))
      end
    end)
  end)
  if started then
    running[key] = obj
  else
    finish()
  end
  return started
end

function M.stop(name, buf)
  local key = name .. ":" .. buf
  if running[key] then
    running[key]:kill(15)
    running[key] = nil
  end
end

return M
