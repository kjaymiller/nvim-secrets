-- Shared masking core: turns a chunk of text into the same text with secrets replaced. Used by
-- both front ends (bat-secrets and rg-secrets) so a rule added once works everywhere.
local detect = require("secrets.detect")
local scanners = require("secrets.scanners")

local M = {}

local warned = {}

---Run one external scanner over `lines` and wait for it.
---@param backend string
---@param lines string[]
---@param name string file name, only the extension matters to some scanners
---@param config table
---@param tool string front-end name, used in warnings
---@return string[] secrets
function M.scan(backend, lines, name, config, tool)
  local def = scanners.defs[backend]
  local cmd = config.commands[backend] or def.cmd
  if vim.fn.executable(cmd) == 0 then
    if not warned[backend] then
      warned[backend] = true
      io.stderr:write(("%s: `%s` not found, skipping it\n"):format(tool or "secrets", cmd))
    end
    return {}
  end
  -- The scanner definitions read from a buffer, so give them a scratch one.
  local buf = vim.api.nvim_create_buf(false, true)
  if name ~= "" then
    pcall(vim.api.nvim_buf_set_name, buf, name)
  end
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  local ok, argv, stdin, cleanup = pcall(def.prepare, buf, cmd)
  vim.api.nvim_buf_delete(buf, { force = true })
  if not ok then
    return {}
  end
  local res = vim.system(argv, { stdin = stdin, text = true }):wait()
  if cleanup then
    cleanup()
  end
  if res.signal ~= 0 then
    return {}
  end
  return vim.fn.uniq(vim.fn.sort(def.parse(res.stdout or "", argv)))
end

---Run every configured external backend over `lines`.
---@return string[] secrets
function M.scan_all(lines, name, config, tool)
  local found = {}
  for _, backend in ipairs(config.backends) do
    if scanners.defs[backend] then
      vim.list_extend(found, M.scan(backend, lines, name, config, tool))
    end
  end
  table.sort(found, function(a, b)
    return #a > #b -- longer secrets first, so a substring can't split one
  end)
  return found
end

---Spans to mask on one plain line, from the lua backend and any scanner-reported literals.
---@param line string
---@param config table
---@param found string[] secrets reported by external scanners (may be empty)
---@return { [1]: integer, [2]: integer }[]
function M.spans(line, config, found, key_lines)
  if key_lines then
    return { { 0, #line } }
  end
  local spans = vim.tbl_contains(config.backends, "lua") and detect.find(line, config) or {}
  vim.list_extend(spans, detect.find_literals(line, found))
  return detect.merge(spans)
end

local function mask_line(line, spans, mask_char)
  local parts, pos = {}, 0
  for _, span in ipairs(spans) do
    table.insert(parts, line:sub(pos + 1, span[1]))
    table.insert(parts, mask_char:rep(vim.fn.strdisplaywidth(line:sub(span[1] + 1, span[2]))))
    pos = span[2]
  end
  table.insert(parts, line:sub(pos + 1))
  return table.concat(parts)
end

---Replace every secret in `text` with mask characters, keeping the line structure.
---@param text string
---@param name string file name, used by scanners that care about the extension
---@param config table options, as in `require("secrets").defaults`
---@param tool? string front-end name for warnings
function M.mask_text(text, name, config, tool)
  local lines = vim.split(text, "\n", { plain = true })
  local found = M.scan_all(lines, name, config, tool)
  local key_lines = #lines <= config.max_lines and detect.private_key_lines(lines) or {}

  local out = {}
  for i, line in ipairs(lines) do
    out[i] = mask_line(line, M.spans(line, config, found, key_lines[i - 1]), config.mask_char)
  end
  return table.concat(out, "\n")
end

---Like `mask_text`, but the lines may contain ANSI colour codes (ripgrep output). Detection runs
---on the visible text; masks are spliced in while the escape sequences are left alone.
---@param text string
---@param name string
---@param config table
---@param tool? string
function M.mask_colored(text, name, config, tool)
  local ansi = require("secrets.ansi")
  local lines = vim.split(text, "\n", { plain = true })
  -- scanners read the visible text, not the escape sequences
  local plain = {}
  for i, line in ipairs(lines) do
    plain[i] = ansi.strip(line).text
  end
  local found = M.scan_all(plain, name, config, tool)
  local key_lines = #lines <= config.max_lines and detect.private_key_lines(plain) or {}

  local out = {}
  for i, line in ipairs(lines) do
    local spans = M.spans(plain[i], config, found, key_lines[i - 1])
    out[i] = ansi.mask(line, spans, function(s)
      return config.mask_char:rep(vim.fn.strdisplaywidth(s))
    end)
  end
  return table.concat(out, "\n")
end

return M
