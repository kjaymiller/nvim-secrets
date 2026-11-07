-- Run: nvim -l tests/rg_spec.lua
vim.opt.rtp:prepend(vim.fn.getcwd())
local rg = require("secrets.rg")

local failures = 0
local function check(name, got, expected)
  if vim.inspect(got) ~= vim.inspect(expected) then
    failures = failures + 1
    print(("FAIL %s\n  expected %s\n  got      %s"):format(name, vim.inspect(expected), vim.inspect(got)))
  end
end

-- parse passes everything that is not ours straight to rg
local opts, args = rg.parse({ "-n", "--hidden", "-C1", "secret", "." })
check("rg args", args, { "-n", "--hidden", "-C1", "secret", "." })
check("default backends", opts.config.backends, { "lua" })
check("no reveal", opts.reveal, false)

-- `--help` (and its aliases) prints our help and exits 0
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
    return rg.main({ flag })
  end)
  check("help flag " .. flag .. " exits 0", ok and code, 0)
  check("help flag " .. flag .. " prints help", out:match("^rg%-secrets:") ~= nil, true)
end

local opts2, args2 = rg.parse({ "--backends", "lua,ripsecrets", "--mask-char=*", "--no-entropy", "--reveal", "foo" })
check("backends", opts2.config.backends, { "lua", "ripsecrets" })
check("mask char", opts2.config.mask_char, "*")
check("entropy off", opts2.config.entropy, false)
check("reveal", opts2.reveal, true)
check("pattern kept", args2, { "foo" })

local opts_p, args_p = rg.parse({ "--patterns", "acme_*,*_secret", "--patterns-file", "/tmp/pat", "foo" })
check("patterns", opts_p.config.patterns, { "acme_*", "*_secret" })
check("patterns file", opts_p.config.patterns_file, "/tmp/pat")
check("patterns pattern kept", args_p, { "foo" })

-- custom patterns are masked through the shared mask core
local pat_config = vim.tbl_extend("force", require("secrets").defaults, { patterns = { "acme_*" } })
local masked_line = require("secrets.mask").mask_text("key acme_1234567890abcdef end", "", pat_config, "rg-secrets")
check("pattern masked", masked_line, "key " .. ("\226\128\162"):rep(21) .. " end")

local opts3, args3 = rg.parse({ "--entropy-threshold", "3.5", "--", "--weird-pattern" })
check("threshold", opts3.config.entropy_threshold, 3.5)
check("after --", args3, { "--", "--weird-pattern" })

-- mask_json only touches the visible line text and drops the stale base64 bytes
local events = table.concat({
  '{"type":"begin","data":{"path":{"text":"a"}}}',
  '{"type":"match","data":{"lines":{"text":"TOKEN=abc123def456\\n","bytes":"VE9LRU4=\\n"},"path":{"text":"a"}}}',
}, "\n")
local masked = rg.mask_json(events, opts.config)
local match_event = vim.json.decode(vim.split(masked, "\n")[2])
check("json masked text", match_event.data.lines.text, "TOKEN=" .. ("•"):rep(12) .. "\n")
check("json bytes dropped", match_event.data.lines.bytes, nil)
check("json begin untouched", vim.split(masked, "\n")[1], vim.split(events, "\n")[1])

-- end to end: run the real rg against a temp file, capturing stdout
if vim.fn.executable("rg") == 1 then
  local path = vim.fn.tempname()
  vim.fn.writefile({ "GITHUB_WEBHOOK_SECRET=f085f4b2c6d36887d46b4d952798a3b71c26a46b", "plain line" }, path)
  local capture = vim.fn.tempname()
  local real = io.stdout
  local f = assert(io.open(capture, "w"))
  io.stdout = f
  local code = rg.main({ "--color=never", "SECRET", path })
  io.stdout = real
  f:close()
  local printed = table.concat(vim.fn.readfile(capture), "\n")
  check("end to end code", code, 0)
  check(
    "end to end masked",
    printed,
    "GITHUB_WEBHOOK_SECRET=" .. ("•"):rep(40)
  )
  os.remove(path)
  os.remove(capture)
end

print(failures == 0 and "ok" or (failures .. " failure(s)"))
os.exit(failures == 0 and 0 or 1)
