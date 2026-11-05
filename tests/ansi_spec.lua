-- Run: nvim -l tests/ansi_spec.lua
vim.opt.rtp:prepend(vim.fn.getcwd())
local ansi = require("secrets.ansi")

local failures = 0
local function check(name, got, expected)
  if got ~= expected then
    failures = failures + 1
    print(("FAIL %s\n  expected %q\n  got      %q"):format(name, expected, got))
  end
end

check("strip plain", ansi.strip("hello").text, "hello")
check("strip csi", ansi.strip("a\27[31mX\27[0mb").text, "aXb")
check("strip osc bel", ansi.strip("\27]8;;http://x\27\\link\27]8;;\27\\").text, "link")
check("strip scs", ansi.strip("\27(Bhi").text, "hi")

local function mask(line, a, b)
  return ansi.mask(line, { { a, b } }, function(s)
    return ("•"):rep(vim.fn.strdisplaywidth(s))
  end)
end

check("mask plain", mask("secretvalue", 0, 11), ("•"):rep(11))
check("mask middle", mask("key=abc123zz", 4, 10), "key=" .. ("•"):rep(6) .. "zz")
check("mask inside colour", mask("GITHUB_", 0, 0), "GITHUB_")
check("mask keeps escapes", mask("GITHUB_\27[31mSECRET\27[0m=x", 0, 0), "GITHUB_\27[31mSECRET\27[0m=x")

-- the real shape: rg colours only the matched word, the secret starts mid-colour
local line = "GITHUB_WEBHOOK_\27[0m\27[1m\27[31mSECRET\27[0m=f085f4b2c6d36887d46b4d952798a3b71c26a46b"
local masked = mask(line, 22, 62)
check(
  "mask coloured assignment",
  ansi.strip(masked).text,
  "GITHUB_WEBHOOK_SECRET=" .. ("•"):rep(40)
)
check("mask keeps escape count", select(2, masked:gsub("\27", "")), select(2, line:gsub("\27", "")))

print(failures == 0 and "ok" or (failures .. " failure(s)"))
os.exit(failures == 0 and 0 or 1)
