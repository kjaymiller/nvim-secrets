-- ripgrep front end: masks secrets in what rg prints, using the same detection and scanners as the
-- Neovim plugin. Run it through bin/rg-secrets.
local mask = require("secrets.mask")

local unpack = table.unpack or unpack

local M = {}

-- rg-secrets options that consume the next argument.
local value_flags = { ["--backends"] = true, ["--mask-char"] = true, ["--entropy-threshold"] = true, ["--patterns"] = true, ["--patterns-file"] = true }

M.help = [[
rg-secrets: ripgrep with secrets masked (display only, files are never changed)

Usage: rg-secrets [secrets options] [rg options] PATTERN [PATH]...

Secrets options (consumed here, everything else goes to rg):
  --help, -h             Show this help (--secrets-help is an alias)
  --rg-help              Show rg's own help
  --reveal               Don't mask anything (same as RG_SECRETS=0)
  --backends LIST        Comma list of: lua, ripsecrets, betterleaks (default: lua)
  --mask-char CHAR       Character used for masking (default: •)
  --no-entropy           Disable the entropy check (lua backend)
  --entropy-threshold N  Bits per character that count as high entropy (default: 4.0)
  --patterns LIST        Comma list of custom glob patterns, e.g. "acme_*,*_secret"
  --patterns-file PATH   File of glob patterns, one per line, `#` for comments

Output is captured from rg and masked before it is printed, so colours, headings, context
lines and --line-number/--column are kept. --json is masked too (the redundant bytes field
is dropped). Modes that don't print file contents (--version) run untouched.

Environment: RG_SECRETS=0 disables masking; RG_SECRETS_BACKENDS, RG_SECRETS_MASK_CHAR,
RG_SECRETS_PATTERNS, RG_SECRETS_PATTERNS_FILE, RG_SECRETS_<BACKEND>_CMD (e.g.
RG_SECRETS_BETTERLEAKS_CMD) set the same options; RG_SECRETS_RG picks the ripgrep executable.
]]

local function fail(msg)
  io.stderr:write("rg-secrets: ", msg, "\n")
  os.exit(2)
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

-- rg modes that never print file contents; run rg untouched.
local function passthrough(rg_args)
  for _, a in ipairs(rg_args) do
    if a == "--version" or a == "-V" or a == "--help" or a == "-h" then
      return true
    end
  end
  return false
end

-- rg needs to be told to colour even though it writes to our pipe, but only when the user did not
-- ask for a specific setting and the output is going to a terminal anyway.
local function color_mode(rg_args)
  for i, a in ipairs(rg_args) do
    local v = a:match("^%-%-color=(.*)$")
    if v then
      return v
    end
    if a == "--color" then
      return rg_args[i + 1]
    end
  end
  return nil
end

local function json_mode(rg_args)
  for _, a in ipairs(rg_args) do
    if a == "--json" then
      return true
    end
  end
  return false
end

---Split argv into our options and the arguments rg gets.
---@param argv string[]
function M.parse(argv)
  local env = vim.env
  local opts = {
    reveal = vim.tbl_contains({ "0", "false", "off" }, env.RG_SECRETS or ""),
    rg = env.RG_SECRETS_RG or "rg",
    config = vim.tbl_extend("force", require("secrets").defaults, { commands = {} }),
  }
  if env.RG_SECRETS_BACKENDS then
    set_option(opts, "--backends", env.RG_SECRETS_BACKENDS)
  end
  if env.RG_SECRETS_MASK_CHAR then
    set_option(opts, "--mask-char", env.RG_SECRETS_MASK_CHAR)
  end
  if env.RG_SECRETS_PATTERNS then
    set_option(opts, "--patterns", env.RG_SECRETS_PATTERNS)
  end
  if env.RG_SECRETS_PATTERNS_FILE then
    set_option(opts, "--patterns-file", env.RG_SECRETS_PATTERNS_FILE)
  end
  for name in pairs(require("secrets.scanners").defs) do
    opts.config.commands[name] = env["RG_SECRETS_" .. name:upper() .. "_CMD"]
  end

  local rg_args = {}
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
      vim.list_extend(rg_args, argv, i)
      break
    else
      table.insert(rg_args, arg)
    end
    i = i + 1
  end

  for _, backend in ipairs(opts.config.backends) do
    if backend ~= "lua" and not require("secrets.scanners").defs[backend] then
      fail("unknown backend: " .. backend)
    end
  end
  return opts, rg_args
end

---Mask a stream of ripgrep --json events. Only the visible line text is touched; the base64
---`bytes` field no longer matches and is dropped.
---@param text string
---@param config table
function M.mask_json(text, config)
  local out = {}
  for line in text:gmatch("[^\n]*") do
    if line ~= "" then
      local ok, event = pcall(vim.json.decode, line)
      local lines = ok and type(event) == "table" and event.data and event.data.lines
      if type(lines) == "table" and type(lines.text) == "string" then
        lines.text = mask.mask_text(lines.text, "", config, "rg-secrets")
        lines.bytes = nil
        out[#out + 1] = vim.json.encode(event)
      else
        out[#out + 1] = line
      end
    end
  end
  return table.concat(out, "\n")
end

-- Does `argv` contain `flag` before the first `--`? Arguments after `--` are data (a pattern
-- or file name), not flags, so they must not trigger help or a passthrough rewrite.
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
  if has_flag(argv, "--rg-help") then
    -- rewrite to --help so the passthrough below runs rg's own help
    local rewritten = {}
    for i, a in ipairs(argv) do
      if a == "--" then
        vim.list_extend(rewritten, argv, i)
        break
      end
      rewritten[#rewritten + 1] = a == "--rg-help" and "--help" or a
    end
    argv = rewritten
  elseif has_flag(argv, "--help") or has_flag(argv, "-h") or has_flag(argv, "--secrets-help") then
    io.stdout:write(M.help)
    return 0
  end
  local opts, rg_args = M.parse(argv)
  if vim.fn.executable(opts.rg) == 0 then
    fail(("`%s` not found on PATH"):format(opts.rg))
  end

  -- --json and --vimgrep imply no colour; forcing it back would corrupt them
  local json = json_mode(rg_args)
  local vimgrep = vim.tbl_contains(rg_args, "--vimgrep")
  local plain = opts.reveal or passthrough(rg_args)
  if not plain and not color_mode(rg_args) and not json and not vimgrep then
    if vim.uv.guess_handle(1) == "tty" then
      table.insert(rg_args, 1, "--color=always")
    end
  end

  local res = vim.system({ opts.rg, unpack(rg_args) }, { text = true }):wait()
  local code = res.signal == 0 and (res.code or 0) or 2
  local stdout = res.stdout or ""
  if plain then
    io.stdout:write(stdout)
  elseif json then
    io.stdout:write(M.mask_json(stdout, opts.config))
  else
    io.stdout:write(mask.mask_colored(stdout, "", opts.config, "rg-secrets"))
  end
  if res.stderr and res.stderr ~= "" then
    io.stderr:write(res.stderr)
  end
  return code
end

return M
