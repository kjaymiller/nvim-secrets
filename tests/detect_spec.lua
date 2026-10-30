-- Run: nvim -l tests/detect_spec.lua
vim.opt.rtp:prepend(vim.fn.getcwd())
local detect = require("secrets.detect")
local opts = { entropy = true, entropy_threshold = 4.0 }

local function text(line)
  local out = {}
  for _, s in ipairs(detect.find(line, opts)) do
    table.insert(out, line:sub(s[1] + 1, s[2]))
  end
  return out
end

local failures = 0
local function check(line, expected)
  local got = text(line)
  if vim.inspect(got) ~= vim.inspect(expected) then
    failures = failures + 1
    print(("FAIL %q\n  expected %s\n  got      %s"):format(line, vim.inspect(expected), vim.inspect(got)))
  end
end

check("key = AKIAIOSFODNN7EXAMPLE", { "AKIAIOSFODNN7EXAMPLE" })
check("export API_KEY=abc123def456", { "abc123def456" })
check([[password: "hunter2hunter2"]], { "hunter2hunter2" })
check("token = os.getenv('TOKEN')", {})
check("password = $PASSWORD", {})
check("DEBUG = true", {})
check("postgres://user:s3cr3tpw@localhost/db", { "s3cr3tpw" })
check("ghp_" .. string.rep("a1B2", 9), { "ghp_" .. string.rep("a1B2", 9) })
check("just a normal line of code", {})
check([[local s = "aB3dE5gH7jK9mN1pQ3sT5vX7"]], { "aB3dE5gH7jK9mN1pQ3sT5vX7" })

local lines = { "a", "-----BEGIN RSA PRIVATE KEY-----", "MIIE", "abc", "-----END RSA PRIVATE KEY-----", "b" }
local inside = detect.private_key_lines(lines)
if not (inside[2] and inside[3] and not inside[1] and not inside[4]) then
  failures = failures + 1
  print("FAIL private key block: " .. vim.inspect(inside))
end

print(failures == 0 and "ok" or (failures .. " failure(s)"))
os.exit(failures == 0 and 0 or 1)
