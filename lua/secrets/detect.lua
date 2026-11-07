local M = {}

-- Token formats with a distinctive prefix. Patterns are Vim "very magic" regexes.
local token_patterns = {
  { name = "aws-access-key", pat = [=[\v<(AKIA|ASIA)[0-9A-Z]{16}>]=] },
  { name = "github-token", pat = [=[\v<gh[pousr]_[A-Za-z0-9]{36,}>]=] },
  { name = "github-pat", pat = [=[\v<github_pat_[A-Za-z0-9_]{22,}>]=] },
  { name = "slack-token", pat = [=[\v<xox[baprs]-[A-Za-z0-9-]{10,}>]=] },
  { name = "stripe-key", pat = [=[\v<[sr]k_(live|test)_[A-Za-z0-9]{16,}>]=] },
  { name = "anthropic-key", pat = [=[\v<sk-ant-[A-Za-z0-9_-]{20,}>]=] },
  { name = "openai-key", pat = [=[\v<sk-(proj-)?[A-Za-z0-9_-]{32,}>]=] },
  { name = "google-api-key", pat = [=[\v<AIza[0-9A-Za-z_-]{35}>]=] },
  { name = "jwt", pat = [=[\v<eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}>]=] },
  { name = "uri-password", pat = [=[\v[a-z][a-z0-9+.-]*://[^:/@[:space:]]+:\zs[^@[:space:]/]+\ze\@]=] },
}

-- Keywords that, when seen left of `=` or `:`, mean the value on the right is a secret. A user's
-- `keyword` rules are appended to this list (see `assignment_pattern`).
local default_keywords = {
  "secret",
  "token",
  "passw(or)?d",
  "passwd",
  "api[_-]?key",
  "key[_-]?file", -- RSA_KEY_FILE=/path/to/key.pem
  "auth",
  "credential",
  "private[_-]?key",
}

local entropy_pat = [=[\v["']\zs[A-Za-z0-9+/_=-]{20,}\ze["']]=]

local placeholders = { "true", "false", "nil", "null", "none", "changeme", "example", "xxxxxx" }

local compiled
local rules_cache -- { signature: string, rules: table }

-- Characters that separate a token from the text around it. Used when a glob pattern contains a
-- `*` or `?`, so a wildcard stops at quotes, spaces and punctuation rather than swallowing the line.
local glob_boundary = [=[^[:space:]"'`=,;:(){}<>*?|\\/]=]

---Build the assignment regex, covering the default keywords plus any user `keyword` rules.
---@param keywords string[]
---@return string
local function assignment_pattern(keywords)
  local all = vim.deepcopy(default_keywords)
  vim.list_extend(all, keywords or {})
  return ([[\v\c(%s)\w*["']?\s*[:=]\s*["']?\zs[^"'[:space:],;()]{6,}]]):format(table.concat(all, "|"))
end

---Turn one glob pattern (`*` = any run of non-separator characters, `?` = one) into a Vim regex.
---The match is anchored with `<`/`>` word boundaries when the glob starts/ends with a word
---character, so a pattern like `acme_*` does not fire inside `xacme_y`. A glob that ends in `*`
---or `?` is left unanchored at that end, so `key-???` matches a three-character suffix rather
---than requiring a boundary after a fixed number of characters. The glob itself is bracketed with
---`\zs`/`\ze` so only it is masked.
---@param glob string
---@return string
local function glob_to_pattern(glob)
  local out = { [=[\v]=] }
  local function word_char(c)
    return c ~= nil and c:match("[%w_]")
  end
  if word_char(glob:sub(1, 1)) then
    out[#out + 1] = "<"
  end
  out[#out + 1] = [=[\zs]=]
  local i = 1
  while i <= #glob do
    local c = glob:sub(i, i)
    if c == "*" then
      out[#out + 1] = "[" .. glob_boundary .. "]*"
    elseif c == "?" then
      out[#out + 1] = "[" .. glob_boundary .. "]"
    else
      -- escape the characters that are special in a "very magic" regex so they match literally
      out[#out + 1] = (c:gsub("[$*.~%[%](){}+^\\/?|<>]", "\\%0"))
    end
    i = i + 1
  end
  out[#out + 1] = [=[\ze]=]
  if word_char(glob:sub(-1)) then
    out[#out + 1] = ">"
  end
  return table.concat(out)
end

local function compile(rules)
  compiled = {
    assignment = vim.regex(assignment_pattern(rules.keywords)),
    entropy = vim.regex(entropy_pat),
    tokens = {},
    custom = {},
  }
  for _, t in ipairs(token_patterns) do
    table.insert(compiled.tokens, vim.regex(t.pat))
  end
  -- raw regex rules are used as-is; glob rules are translated first
  local custom = vim.deepcopy(rules.regexes or {})
  vim.list_extend(custom, vim.tbl_map(glob_to_pattern, rules.globs or {}))
  for _, pat in ipairs(custom) do
    local ok, re = pcall(vim.regex, pat)
    if ok then
      table.insert(compiled.custom, re)
    end
  end
end

---Shannon entropy in bits per character.
function M.entropy(s)
  local counts, n = {}, #s
  for i = 1, n do
    local c = s:byte(i)
    counts[c] = (counts[c] or 0) + 1
  end
  local h = 0
  for _, count in pairs(counts) do
    local p = count / n
    h = h - p * math.log(p, 2)
  end
  return h
end

local function is_placeholder(value)
  if value:sub(1, 1) == "$" or value:sub(1, 1) == "{" then
    return true
  end
  local lower = value:lower()
  for _, p in ipairs(placeholders) do
    if lower == p or lower:find("^" .. p) and #lower <= #p + 2 then
      return true
    end
  end
  return false
end

local function each_match(re, line, fn)
  local init = 0
  while init < #line do
    local s, e = re:match_str(line:sub(init + 1))
    if not s then
      return
    end
    fn(init + s, init + e)
    init = init + math.max(e, s + 1)
  end
end

---Parse a rules file into `{ globs, keywords, regexes }`. One rule per line; blank lines and
---lines starting with `#` are ignored. A line is `glob <pattern>`, `keyword <name>`,
---`regex <vim-regex>`, or a bare pattern (treated as a glob).
---@param path string
---@return { globs: string[], keywords: string[], regexes: string[] }
function M.load_rules_file(path)
  local rules = { globs = {}, keywords = {}, regexes = {} }
  local f = io.open(vim.fn.expand(path), "r")
  if not f then
    return rules
  end
  for line in f:lines() do
    local text = vim.trim(line)
    if text ~= "" and text:sub(1, 1) ~= "#" then
      local kind, body = text:match("^(%w+)%s+(.*)$")
      if kind == "glob" and body ~= "" then
        table.insert(rules.globs, body)
      elseif kind == "keyword" and body ~= "" then
        table.insert(rules.keywords, body)
      elseif kind == "regex" and body ~= "" then
        table.insert(rules.regexes, body)
      elseif kind and vim.tbl_contains({ "glob", "keyword", "regex" }, kind) then
        -- an empty rule of a known kind, ignore
      else
        -- no recognised prefix: the whole line is a glob
        table.insert(rules.globs, text)
      end
    end
  end
  f:close()
  return rules
end

---Default rules file location, used when one exists. Kept simple: a single path under the user's
---config directory. `vim.fn.stdpath("config")` is `~/.config/nvim` normally, so this resolves to
---`~/.config/nvim/secrets-patterns.txt` alongside the user's Neovim config.
---@return string|nil
function M.default_rules_file()
  local path = vim.fs.joinpath(vim.fn.stdpath("config"), "secrets-patterns.txt")
  if vim.uv.fs_stat(vim.fn.expand(path)) then
    return path
  end
  return nil
end

---@param dst { globs: string[], keywords: string[], regexes: string[] }
---@param src { globs: string[], keywords: string[], regexes: string[] }
local function merge_rules(dst, src)
  vim.list_extend(dst.globs, src.globs)
  vim.list_extend(dst.keywords, src.keywords)
  vim.list_extend(dst.regexes, src.regexes)
end

---Merge `config.patterns` (globs) with the rules in `config.patterns_file` and, if present, the
---default rules file. The result is cached by the inputs, so mutating a config table (as the
---front ends and tests do) is still picked up, while per-line calls don't re-read files.
---@param config table
---@return { globs: string[], keywords: string[], regexes: string[] }
function M.resolve_rules(config)
  local globs = config.patterns or {}
  local file = config.patterns_file
  local default = M.default_rules_file()
  local signature = table.concat(globs, "\0") .. "\1" .. (file or "") .. "\2" .. (default or "")
  if rules_cache and rules_cache.signature == signature then
    return rules_cache.rules
  end
  local rules = { globs = vim.deepcopy(globs), keywords = {}, regexes = {} }
  if file then
    merge_rules(rules, M.load_rules_file(file))
  end
  if default then
    merge_rules(rules, M.load_rules_file(default))
  end
  rules_cache = { signature = signature, rules = rules }
  return rules
end

---Find secret-looking spans in one line.
---@param line string
---@param opts { entropy: boolean, entropy_threshold: number, patterns?: string[] }
---@return { [1]: integer, [2]: integer }[] spans 0-based byte [start, end) pairs, sorted and non-overlapping
function M.find(line, opts)
  local rules = M.resolve_rules(opts)
  local signature = table.concat(rules.globs, "\0") .. "\3" .. table.concat(rules.keywords, "\0") .. "\3" .. table.concat(rules.regexes, "\0")
  if not compiled or compiled.signature ~= signature then
    compile(rules)
    compiled.signature = signature
  end
  local spans = {}
  local function add(s, e)
    if s < e and not is_placeholder(line:sub(s + 1, e)) then
      table.insert(spans, { s, e })
    end
  end

  for _, re in ipairs(compiled.tokens) do
    each_match(re, line, add)
  end
  for _, re in ipairs(compiled.custom) do
    each_match(re, line, add)
  end
  each_match(compiled.assignment, line, function(s, e)
    if line:sub(e + 1, e + 1) ~= "(" then -- a function call, not a literal
      add(s, e)
    end
  end)
  if opts.entropy then
    each_match(compiled.entropy, line, function(s, e)
      if M.entropy(line:sub(s + 1, e)) >= opts.entropy_threshold then
        add(s, e)
      end
    end)
  end

  return M.merge(spans)
end

---Sort spans and merge overlapping ones.
---@param spans { [1]: integer, [2]: integer }[]
function M.merge(spans)
  table.sort(spans, function(a, b)
    return a[1] < b[1]
  end)
  local merged = {}
  for _, span in ipairs(spans) do
    local last = merged[#merged]
    if last and span[1] < last[2] then
      last[2] = math.max(last[2], span[2])
    else
      table.insert(merged, { span[1], span[2] })
    end
  end
  return merged
end

---Spans of every plain-text occurrence of the given secrets in a line.
---@param line string
---@param secrets string[]
function M.find_literals(line, secrets)
  local spans = {}
  for _, secret in ipairs(secrets) do
    local init = 1
    while true do
      local s, e = line:find(secret, init, true)
      if not s then
        break
      end
      table.insert(spans, { s - 1, e })
      init = e + 1
    end
  end
  return spans
end

---Find 0-based line numbers inside PEM private key blocks (BEGIN/END lines excluded).
---@param lines string[]
---@return table<integer, true>
function M.private_key_lines(lines)
  local inside, start = {}, nil
  for i, line in ipairs(lines) do
    if line:find("-----BEGIN [%u ]*PRIVATE KEY-----") then
      start = i
    elseif start and line:find("-----END [%u ]*PRIVATE KEY-----") then
      for j = start + 1, i - 1 do
        inside[j - 1] = true
      end
      start = nil
    end
  end
  return inside
end

return M
