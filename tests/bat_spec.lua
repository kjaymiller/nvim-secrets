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

local opts, bat_args, files = bat.parse({ "--backends", "lua", "-n", "--paging", "never", "--no-entropy", "a.py", "b.py" })
check("parse files", files, { "a.py", "b.py" })
check("parse bat args", bat_args, { "-n", "--paging", "never" })
check("parse backends", opts.config.backends, { "lua" })
check("parse entropy", opts.config.entropy, false)
local opts2, _, files2 = bat.parse({ "--mask-char=*", "--reveal", "--", "-weird-name" })
check("parse inline value", opts2.config.mask_char, "*")
check("parse reveal", opts2.reveal, true)
check("parse after --", files2, { "-weird-name" })

print(failures == 0 and "ok" or (failures .. " failure(s)"))
os.exit(failures == 0 and 0 or 1)
