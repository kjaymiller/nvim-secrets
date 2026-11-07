-- Run: nvim -l tests/bat_spec.lua
vim.opt.rtp:prepend(vim.fn.getcwd())
local bat = require("secrets.bat")
local config = vim.tbl_extend("force", require("secrets").defaults, { commands = {} })

local failures = 0
local function check(name, got, expected)
  if vim.inspect(got) ~= vim.inspect(expected) then
    failures = failures + 1
    print(("FAIL %s\n  expected %s\n  got      %s"):format(name, vim.inspect(expected), vim.inspect(got)))
  end
end

local function mask(text)
  return bat.mask_text(text, "", config)
end

check("assignment", mask("export API_KEY=abc123def456"), "export API_KEY=" .. ("•"):rep(12))
check("uri password", mask("postgres://user:s3cr3tpw@host/db"), "postgres://user:" .. ("•"):rep(8) .. "@host/db")
check("plain line", mask("just a normal line\nDEBUG = true\n"), "just a normal line\nDEBUG = true\n")
check("trailing newline kept", mask("a\n"), "a\n")
check(
  "private key",
  mask("a\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"),
  "a\n-----BEGIN RSA PRIVATE KEY-----\n••••\n-----END RSA PRIVATE KEY-----"
)
check("custom mask char", bat.mask_text("token = hunter2hunter2", "", vim.tbl_extend("force", config, { mask_char = "*" })), "token = " .. ("*"):rep(14))

-- custom glob patterns
local pat_config = vim.tbl_extend("force", config, { patterns = { "acme_*" } })
check("pattern masked", bat.mask_text("key acme_1234567890abcdef end", "", pat_config), "key " .. ("\226\128\162"):rep(21) .. " end")
check("pattern not matched", bat.mask_text("key other_1234567890abcdef end", "", pat_config), "key other_1234567890abcdef end")
local pat_file = vim.fn.tempname()
vim.fn.writefile({ "# comment", "acme_*" }, pat_file)
local file_config = vim.tbl_extend("force", config, { patterns_file = pat_file })
check("pattern file masked", bat.mask_text("key acme_1234567890abcdef end", "", file_config), "key " .. ("\226\128\162"):rep(21) .. " end")
os.remove(pat_file)

local opts, bat_args, files = bat.parse({ "--backends", "lua", "-n", "--paging", "never", "--no-entropy", "a.py", "b.py" })
check("parse files", files, { "a.py", "b.py" })
check("parse bat args", bat_args, { "-n", "--paging", "never" })
check("parse backends", opts.config.backends, { "lua" })
check("parse entropy", opts.config.entropy, false)
local opts_p, _, _ = bat.parse({ "--patterns", "acme_*,*_secret", "--patterns-file", "/tmp/pat", "file" })
check("parse patterns", opts_p.config.patterns, { "acme_*", "*_secret" })
check("parse patterns file", opts_p.config.patterns_file, "/tmp/pat")
local opts2, _, files2 = bat.parse({ "--mask-char=*", "--reveal", "--", "-weird-name" })
check("parse inline value", opts2.config.mask_char, "*")
check("parse reveal", opts2.reveal, true)
check("parse after --", files2, { "-weird-name" })

-- `--help` (and its aliases) prints our help and exits 0; `--bat-help` is passed on to bat
local function capture_stdout(fn)
  local path = vim.fn.tempname()
  local real = io.stdout
  local f = assert(io.open(path, "w"))
  io.stdout = f
  local ok, code = pcall(fn)
  io.stdout = real
  f:close()
  return ok, code, table.concat(vim.fn.readfile(path), "\n")
end

for _, flag in ipairs({ "--help", "-h", "--secrets-help" }) do
  local ok, code, out = capture_stdout(function()
    return bat.main({ flag })
  end)
  check("help flag " .. flag .. " exits 0", ok and code, 0)
  check("help flag " .. flag .. " prints help", out:match("^bat%-secrets:") ~= nil, true)
end

print(failures == 0 and "ok" or (failures .. " failure(s)"))
os.exit(failures == 0 and 0 or 1)
