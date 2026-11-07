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
check("RSA_KEY_FILE=/home/u/.ssh/id_rsa", { "/home/u/.ssh/id_rsa" })
check("RSA_KEY_FILE=~/.ssh/id_rsa", { "~/.ssh/id_rsa" })
check([[export RSA_KEY_FILE="key.pem"]], { "key.pem" })
check("MY_RSA_KEY_FILE=/etc/key.pem", { "/etc/key.pem" })
check("KEY_FILE=/etc/x.pem", { "/etc/x.pem" })
check([[password: "hunter2hunter2"]], { "hunter2hunter2" })
check("token = os.getenv('TOKEN')", {})
check("password = $PASSWORD", {})
check("DEBUG = true", {})
check("postgres://user:s3cr3tpw@localhost/db", { "s3cr3tpw" })
check("ghp_" .. string.rep("a1B2", 9), { "ghp_" .. string.rep("a1B2", 9) })
check("just a normal line of code", {})
check([[local s = "aB3dE5gH7jK9mN1pQ3sT5vX7"]], { "aB3dE5gH7jK9mN1pQ3sT5vX7" })

-- custom glob patterns
local function text_with(line, patterns)
  local out = {}
  for _, s in ipairs(detect.find(line, { entropy = true, entropy_threshold = 4.0, patterns = patterns })) do
    table.insert(out, line:sub(s[1] + 1, s[2]))
  end
  return out
end

local function check_pat(line, patterns, expected)
  local got = text_with(line, patterns)
  if vim.inspect(got) ~= vim.inspect(expected) then
    failures = failures + 1
    print(("FAIL %q with %s\n  expected %s\n  got      %s"):format(line, vim.inspect(patterns), vim.inspect(expected), vim.inspect(got)))
  end
end

check_pat("acme_1234567890abcdef", { "acme_*" }, { "acme_1234567890abcdef" })
check_pat('token = "acme_1234567890abcdef"', { "acme_*" }, { "acme_1234567890abcdef" })
check_pat("prefix_acme_1234567890abcdef", { "acme_*" }, {})
check_pat("RADIUS_API_KEY_1_value", { "RADIUS_*" }, { "RADIUS_API_KEY_1_value" })
check_pat("abc_secret_xyz", { "*_secret_*" }, { "abc_secret_xyz" })
check_pat("key-ab12cd", { "key-???" }, { "key-ab1" })
check_pat('key-ab, other', { "key-??" }, { "key-ab" })
check_pat("nothing here", { "acme_*" }, {})

-- bare `*` should not leak across separators like spaces or quotes
check_pat('a = "plain" acme_value', { "acme_*" }, { "acme_value" })

-- word anchors: a pattern starting/ending with a word character does not fire inside a longer token
check_pat("xacme_y", { "acme_*" }, {})
check_pat("xacme_yz", { "*acme_*" }, { "xacme_yz" })
-- a trailing `*`/`?` leaves that end open, so `key-???` matches a short suffix
check_pat("key-ab, other", { "key-??" }, { "key-ab" })
-- literals that are special in a very-magic regex still match literally
check_pat("a [abc] b", { "[abc]" }, { "[abc]" })
check_pat("a.b_c", { "a.b_*" }, { "a.b_c" })
-- a lone wildcard produces no zero-width matches
check_pat("one two", { "*" }, { "one", "two" })

-- no patterns behaves exactly as before
check_pat("key = AKIAIOSFODNN7EXAMPLE", {}, { "AKIAIOSFODNN7EXAMPLE" })

-- rules file loading
local patterns_path = vim.fn.tempname()
vim.fn.writefile({
  "# comment",
  "",
  "acme_*",
  "  *_token  ",
  "glob bare_*",
  "keyword MY_CUSTOM_SECRET",
  "regex \\v<zp-[A-Za-z0-9]{8}>",
}, patterns_path)
local loaded = detect.load_rules_file(patterns_path)
local expected_rules = {
  globs = { "acme_*", "*_token", "bare_*" },
  keywords = { "MY_CUSTOM_SECRET" },
  regexes = { "\\v<zp-[A-Za-z0-9]{8}>" },
}
if vim.inspect(loaded) ~= vim.inspect(expected_rules) then
  failures = failures + 1
  print("FAIL load_rules_file: " .. vim.inspect(loaded))
end

-- a rules file resolves through find: globs, keywords and regexes all apply
local function text_rules(line, config)
  local out = {}
  for _, s in ipairs(detect.find(line, vim.tbl_extend("force", { entropy = false, entropy_threshold = 4.0 }, config))) do
    table.insert(out, line:sub(s[1] + 1, s[2]))
  end
  return out
end
local rules_config = { entropy = false, entropy_threshold = 4.0, patterns_file = patterns_path }
local function check_rules(line, expected)
  local got = text_rules(line, rules_config)
  if vim.inspect(got) ~= vim.inspect(expected) then
    failures = failures + 1
    print(("FAIL %q with rules file\n  expected %s\n  got      %s"):format(line, vim.inspect(expected), vim.inspect(got)))
  end
end
check_rules("a acme_1234567890abcdef b", { "acme_1234567890abcdef" })
check_rules("a bare_xyz b", { "bare_xyz" })
check_rules("MY_CUSTOM_SECRET=abcdef123456", { "abcdef123456" })
check_rules("a zp-deadbeef b", { "zp-deadbeef" })
check_rules("a zp-dead b", {})
os.remove(patterns_path)

-- resolve_rules merges the shorthand `patterns` list with the file
local resolved_path = vim.fn.tempname()
vim.fn.writefile({ "keyword FILE_KEY", "customsekrit_*" }, resolved_path)
local resolved = detect.resolve_rules({ patterns = { "acme_*" }, patterns_file = resolved_path })
local expected_resolved = { globs = { "acme_*", "customsekrit_*" }, keywords = { "FILE_KEY" }, regexes = {} }
if vim.inspect(resolved) ~= vim.inspect(expected_resolved) then
  failures = failures + 1
  print("FAIL resolve_rules: " .. vim.inspect(resolved))
end
os.remove(resolved_path)

-- the shipped example file parses (all rules are commented out, so it is empty)
local example_rules = detect.load_rules_file(vim.fn.getcwd() .. "/patterns.txt")
if vim.inspect(example_rules) ~= vim.inspect({ globs = {}, keywords = {}, regexes = {} }) then
  failures = failures + 1
  print("FAIL shipped patterns.txt: " .. vim.inspect(example_rules))
end

-- default rules file is picked up when present
local default_path = vim.fs.joinpath(vim.fn.stdpath("config"), "secrets-patterns.txt")
vim.fn.writefile({ "keyword DEFAULT_FILE_KEY" }, default_path)
local default_line = "DEFAULT_FILE_KEY=abcdef123456"
local default_masked = {}
for _, s in ipairs(detect.find(default_line, { entropy = false, entropy_threshold = 4.0 })) do
  default_masked[#default_masked + 1] = default_line:sub(s[1] + 1, s[2])
end
if vim.inspect(default_masked) ~= vim.inspect({ "abcdef123456" }) then
  failures = failures + 1
  print("FAIL default rules file: " .. vim.inspect(default_masked))
end
os.remove(default_path)

local lines = { "a", "-----BEGIN RSA PRIVATE KEY-----", "MIIE", "abc", "-----END RSA PRIVATE KEY-----", "b" }
local inside = detect.private_key_lines(lines)
if not (inside[2] and inside[3] and not inside[1] and not inside[4]) then
  failures = failures + 1
  print("FAIL private key block: " .. vim.inspect(inside))
end

print(failures == 0 and "ok" or (failures .. " failure(s)"))
os.exit(failures == 0 and 0 or 1)
