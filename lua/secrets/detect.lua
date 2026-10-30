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

local function compile()
  compiled = { assignment = vim.regex(assignment_pat), entropy = vim.regex(entropy_pat), tokens = {} }
  for _, t in ipairs(token_patterns) do
    table.insert(compiled.tokens, vim.regex(t.pat))
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

---Find secret-looking spans in one line.
---@param line string
---@param opts { entropy: boolean, entropy_threshold: number }
---@return { [1]: integer, [2]: integer }[] spans 0-based byte [start, end) pairs, sorted and non-overlapping
function M.find(line, opts)
  if not compiled then
    compile()
  end
  local spans = {}
  local function add(s, e)
    if not is_placeholder(line:sub(s + 1, e)) then
      table.insert(spans, { s, e })
    end
  end

  for _, re in ipairs(compiled.tokens) do
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
