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

-- `secret = "value"`, `API_KEY: value`, `export TOKEN=value` ...
local assignment_pat = [=[\v\c(secret|token|passw(or)?d|passwd|api[_-]?key|auth|credential|private[_-]?key)\w*["']?\s*[:=]\s*["']?\zs[^"'[:space:],;()]{6,}]=]

local entropy_pat = [=[\v["']\zs[A-Za-z0-9+/_=-]{20,}\ze["']]=]

local placeholders = { "true", "false", "nil", "null", "none", "changeme", "example", "xxxxxx" }

local compiled
local pattern_cache -- { signature: string, patterns: string[] }

-- Characters that separate a token from the text around it. Used when a glob pattern contains a
-- `*` or `?`, so a wildcard stops at quotes, spaces and punctuation rather than swallowing the line.
local glob_boundary = [=[^[:space:]"'`=,;:(){}<>*?|\\/]=]

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

local function compile(patterns)
  compiled = { assignment = vim.regex(assignment_pat), entropy = vim.regex(entropy_pat), tokens = {}, custom = {} }
  for _, t in ipairs(token_patterns) do
    table.insert(compiled.tokens, vim.regex(t.pat))
  end
  for _, glob in ipairs(patterns or {}) do
    local ok, re = pcall(vim.regex, glob_to_pattern(glob))
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

---Read a patterns file: one glob per line, `#` comments and blank lines ignored.
---@param path string
---@return string[]
function M.load_patterns_file(path)
  local f = io.open(vim.fn.expand(path), "r")
  if not f then
    return {}
  end
  local patterns = {}
  for line in f:lines() do
    local pat = vim.trim(line)
    if pat ~= "" and pat:sub(1, 1) ~= "#" then
      table.insert(patterns, pat)
    end
  end
  f:close()
  return patterns
end

---Merge `config.patterns` with the patterns in `config.patterns_file` (if any). The merged list
---is cached by the `patterns`/`patterns_file` inputs, so mutating a config table (as the front
---ends and tests do) is still picked up, while per-line calls don't re-read the file.
---@param config table
---@return string[]
function M.resolve_patterns(config)
  local patterns = config.patterns or {}
  local signature = table.concat(patterns, "\0") .. "\1" .. (config.patterns_file or "")
  if pattern_cache and pattern_cache.signature == signature then
    return pattern_cache.patterns
  end
  local merged = vim.deepcopy(patterns)
  if config.patterns_file then
    vim.list_extend(merged, M.load_patterns_file(config.patterns_file))
  end
  pattern_cache = { signature = signature, patterns = merged }
  return merged
end

---Find secret-looking spans in one line.
---@param line string
---@param opts { entropy: boolean, entropy_threshold: number, patterns?: string[] }
---@return { [1]: integer, [2]: integer }[] spans 0-based byte [start, end) pairs, sorted and non-overlapping
function M.find(line, opts)
  local patterns = M.resolve_patterns(opts)
  local signature = table.concat(patterns, "\0")
  if not compiled or compiled.signature ~= signature then
    compile(patterns)
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
