-- bat front end: masks secrets in the text bat is about to show, using the same detection and
-- scanners as the Neovim plugin. Run it through bin/bat-secrets.
local detect = require("secrets.detect")
local scanners = require("secrets.scanners")

local M = {}

local function set(list)
  local s = {}
  for _, v in ipairs(list) do
    s[v] = true
  end
  return s
end

-- bat options that consume the next argument, so it is not mistaken for a file.
local bat_value_flags = set({
  "-l", "--language", "-H", "--highlight-line", "--file-name", "--diff-context", "--tabs",
  "--wrap", "--terminal-width", "--color", "--italic-text", "--decorations", "--paging",
  "--pager", "-m", "--map-syntax", "--ignored-suffix", "--theme", "--theme-light",
  "--theme-dark", "--squeeze-limit", "--strip-ansi", "--style", "-r", "--line-range",
  "--nonprintable-notation", "--binary", "--completion",
}) -- stylua: ignore

-- bat options that don't render files; bat runs untouched.
local bat_passthrough = set({
  "-h", "--help", "-V", "--version", "--list-languages", "-L", "--list-themes",
  "--config-file", "--config-dir", "--cache-dir", "--diagnostic", "--acknowledgements",
  "--build-cache", "--clear-cache", "--completion",
}) -- stylua: ignore

-- bat-secrets options that consume the next argument.
local value_flags = set({ "--backends", "--mask-char", "--entropy-threshold", "--patterns", "--patterns-file" })

M.help = [[
bat-secrets: bat with secrets masked (display only, files are never changed)

Usage: bat-secrets [secrets options] [bat options] [FILE]...

Secrets options (consumed here, everything else goes to bat):
  --help, -h             Show this help (--secrets-help is an alias)
  --bat-help             Show bat's own help
  --reveal               Don't mask anything (same as BAT_SECRETS=0)
  --backends LIST        Comma list of: lua, ripsecrets, betterleaks (default: lua)
  --mask-char CHAR       Character used for masking (default: •)
  --no-entropy           Disable the entropy check (lua backend)
  --entropy-threshold N  Bits per character that count as high entropy (default: 4.0)
  --patterns LIST        Comma list of custom glob patterns, e.g. "acme_*,*_secret"
  --patterns-file PATH   File of glob patterns, one per line, `#` for comments

Environment: BAT_SECRETS=0 disables masking; BAT_SECRETS_BACKENDS, BAT_SECRETS_MASK_CHAR,
BAT_SECRETS_PATTERNS, BAT_SECRETS_PATTERNS_FILE, BAT_SECRETS_<BACKEND>_CMD (e.g.
BAT_SECRETS_BETTERLEAKS_CMD) set the same options; BAT_SECRETS_BAT picks the bat executable.
]]

local function fail(msg)
  io.stderr:write("bat-secrets: ", msg, "\n")
  os.exit(1)
end

local function set_option(opts, flag, value)
  if flag == "--backends" then
    opts.config.backends = vim.split(value, ",", { plain = true, trimempty = true })
  elseif flag == "--mask-char" then
    opts.config.mask_char = value ~= "" and vim.fn.strcharpart(value, 0, 1) or opts.config.mask_char
  elseif flag == "--patterns" then
    opts.config.patterns = vim.split(value, ",", { plain = true, trimempty = true })
  elseif flag == "--patterns-file" then
    opts.config.patterns_file = value
  else
    opts.config.entropy_threshold = tonumber(value) or fail("--entropy-threshold needs a number")
  end
end

---Split argv into our options, the options bat gets, and the files to show.
---@param argv string[]
function M.parse(argv)
  local env = vim.env
  local opts = {
    reveal = vim.tbl_contains({ "0", "false", "off" }, env.BAT_SECRETS or ""),
    bat = env.BAT_SECRETS_BAT or "bat",
    config = vim.tbl_extend("force", require("secrets").defaults, { commands = {} }),
  }
  if env.BAT_SECRETS_BACKENDS then
    set_option(opts, "--backends", env.BAT_SECRETS_BACKENDS)
  end
  if env.BAT_SECRETS_MASK_CHAR then
    set_option(opts, "--mask-char", env.BAT_SECRETS_MASK_CHAR)
  end
  if env.BAT_SECRETS_PATTERNS then
    set_option(opts, "--patterns", env.BAT_SECRETS_PATTERNS)
  end
  if env.BAT_SECRETS_PATTERNS_FILE then
    set_option(opts, "--patterns-file", env.BAT_SECRETS_PATTERNS_FILE)
  end
  for name in pairs(scanners.defs) do
    opts.config.commands[name] = env["BAT_SECRETS_" .. name:upper() .. "_CMD"]
  end

  local bat_args, files = {}, {}
  local i = 1
  while i <= #argv do
    local arg = argv[i]
    local flag, inline = arg:match("^(%-%-[%w-]+)=(.*)$")
    if arg == "--reveal" then
      opts.reveal = true
    elseif arg == "--no-entropy" then
      opts.config.entropy = false
    elseif value_flags[arg] then
      i = i + 1
      set_option(opts, arg, argv[i] or fail(arg .. " needs a value"))
    elseif flag and value_flags[flag] then
      set_option(opts, flag, inline)
    elseif arg == "--" then
      vim.list_extend(files, argv, i + 1)
      break
    elseif bat_value_flags[arg] then
      i = i + 1
      vim.list_extend(bat_args, { arg, argv[i] or "" })
    elseif arg:sub(1, 1) == "-" and arg ~= "-" then
      table.insert(bat_args, arg)
    else
      table.insert(files, arg)
    end
    i = i + 1
  end

  for _, backend in ipairs(opts.config.backends) do
    if backend ~= "lua" and not scanners.defs[backend] then
      fail("unknown backend: " .. backend)
    end
  end
  return opts, bat_args, files
end

local warned = {}

---Run one external scanner over `lines` and wait for it.
---@return string[] secrets
function M.scan(backend, lines, name, config)
  local def = scanners.defs[backend]
  local cmd = config.commands[backend] or def.cmd
  if vim.fn.executable(cmd) == 0 then
    if not warned[backend] then
      warned[backend] = true
      io.stderr:write(("bat-secrets: `%s` not found, skipping it\n"):format(cmd))
    end
    return {}
  end
  -- The scanner definitions read from a buffer, so give them a scratch one.
  local buf = vim.api.nvim_create_buf(false, true)
  if name ~= "" then
    pcall(vim.api.nvim_buf_set_name, buf, name) -- only the extension matters, to ripsecrets
  end
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  local ok, argv, stdin, cleanup = pcall(def.prepare, buf, cmd)
  vim.api.nvim_buf_delete(buf, { force = true })
  if not ok then
    return {}
  end
  local res = vim.system(argv, { stdin = stdin, text = true }):wait()
  if cleanup then
    cleanup()
  end
  if res.signal ~= 0 then
    return {}
  end
  return vim.fn.uniq(vim.fn.sort(def.parse(res.stdout or "", argv)))
end

local function mask_line(line, spans, mask_char)
  local parts, pos = {}, 0
  for _, span in ipairs(spans) do
    table.insert(parts, line:sub(pos + 1, span[1]))
    table.insert(parts, mask_char:rep(vim.fn.strdisplaywidth(line:sub(span[1] + 1, span[2]))))
    pos = span[2]
  end
  table.insert(parts, line:sub(pos + 1))
  return table.concat(parts)
end

---Replace every secret in `text` with mask characters, keeping the line structure.
---@param text string
---@param name string file name, used by scanners that care about the extension
---@param config table options, as in `require("secrets").defaults`
function M.mask_text(text, name, config)
  local lines = vim.split(text, "\n", { plain = true })
  local use_lua = vim.tbl_contains(config.backends, "lua")
  local found = {}
  for _, backend in ipairs(config.backends) do
    if scanners.defs[backend] then
      vim.list_extend(found, M.scan(backend, lines, name, config))
    end
  end
  table.sort(found, function(a, b)
    return #a > #b -- longer secrets first, so a substring can't split one
  end)
  local key_lines = #lines <= config.max_lines and detect.private_key_lines(lines) or {}

  local out = {}
  for i, line in ipairs(lines) do
    local spans
    if key_lines[i - 1] then
      spans = { { 0, #line } }
    else
      spans = use_lua and detect.find(line, config) or {}
      vim.list_extend(spans, detect.find_literals(line, found))
      spans = detect.merge(spans)
    end
    out[i] = mask_line(line, spans, config.mask_char)
  end
  return table.concat(out, "\n")
end

---Run bat with our stdout/stderr, feeding it `input` on stdin when given.
---@return integer exit code
local function run(bat, args, input)
  local stdin = input and vim.uv.new_pipe() or nil
  local code
  local handle = vim.uv.spawn(bat, { args = args, stdio = { stdin or 0, 1, 2 } }, function(c)
    code = c
  end)
  if not handle then
    fail(("`%s` not found"):format(bat))
  end
  if stdin then
    -- bat may quit early (a pager closed with q), so a failed write is not an error
    stdin:write(input, function()
      stdin:shutdown(function()
        stdin:close()
      end)
    end)
  end
  vim.wait(2 ^ 31 - 1, function()
    return code ~= nil
  end, 5)
  handle:close()
  return code
end

-- Does `argv` contain `flag` before the first `--`? Arguments after `--` are data (a file
-- name), not flags, so they must not trigger help or a passthrough rewrite.
local function has_flag(argv, flag)
  for _, a in ipairs(argv) do
    if a == "--" then
      return false
    end
    if a == flag then
      return true
    end
  end
  return false
end

---@param argv string[]
---@return integer exit code
function M.main(argv)
  if has_flag(argv, "--bat-help") then
    -- rewrite to --help so the passthrough below runs bat's own help
    local rewritten = {}
    for i, a in ipairs(argv) do
      if a == "--" then
        vim.list_extend(rewritten, argv, i)
        break
      end
      rewritten[#rewritten + 1] = a == "--bat-help" and "--help" or a
    end
    argv = rewritten
  elseif has_flag(argv, "--help") or has_flag(argv, "-h") or has_flag(argv, "--secrets-help") then
    io.stdout:write(M.help)
    return 0
  end
  local opts, bat_args, files = M.parse(argv)
  if vim.fn.executable(opts.bat) == 0 then
    fail(("`%s` not found on PATH"):format(opts.bat))
  end

  if opts.reveal or vim.iter(bat_args):any(function(a)
    return bat_passthrough[a]
  end) then
    return run(opts.bat, vim.list_extend(bat_args, files))
  end

  local function show(text, name, path)
    local args = vim.list_extend({}, bat_args)
    if path and not vim.tbl_contains(bat_args, "--file-name") then
      vim.list_extend(args, { "--file-name", path })
    end
    return run(opts.bat, args, M.mask_text(text, name, opts.config))
  end

  if #files == 0 or (#files == 1 and files[1] == "-") then
    -- keep the user's own --file-name, which scanners and bat use to pick a syntax
    local name = ""
    for j, a in ipairs(bat_args) do
      if a == "--file-name" then
        name = bat_args[j + 1] or ""
      end
    end
    return show(io.read("*a") or "", name)
  end

  local status = 0
  for _, path in ipairs(files) do
    local f, err = io.open(path, "rb")
    local text = f and f:read("*a")
    if f then
      f:close()
    end
    if text then
      status = show(text, path, path) ~= 0 and 1 or status
    else
      io.stderr:write("bat-secrets: ", err or (path .. ": could not read"), "\n")
      status = 1
    end
  end
  return status
end

return M
