-- ANSI-aware helpers. ripgrep colours matches, so masking has to walk around escape sequences:
-- they take no space on screen and must survive in the output, while the secret bytes between them
-- are replaced.
local M = {}

---Length of the ANSI sequence starting at byte index `i` (1-based), or nil if none.
---Handles CSI, OSC (and the two-byte/`ESC`-prefixed forms), which is what ripgrep emits.
---@param s string
---@param i integer
---@return integer? length
local function escape_length(s, i)
  if s:byte(i) ~= 0x1b then
    return nil
  end
  local b = s:byte(i + 1)
  if b == nil then
    return 1
  elseif b == 0x5b then -- ESC [  CSI: params/intermediates then a final byte 0x40-0x7e
    local j = i + 2
    while true do
      local c = s:byte(j)
      if c == nil then
        return j - i
      end
      if c >= 0x40 and c <= 0x7e then
        return j - i + 1
      end
      j = j + 1
    end
  elseif b == 0x5d then -- ESC ]  OSC: until BEL or ST (ESC \\)
    local j = i + 2
    while j <= #s do
      local c = s:byte(j)
      if c == 0x07 then
        return j - i + 1
      end
      if c == 0x1b and s:byte(j + 1) == 0x5c then
        return j - i + 2
      end
      j = j + 1
    end
    return #s - i + 1
  elseif b >= 0x40 and b <= 0x5f then -- single-character escape
    return 2
  else -- ESC + intermediates (0x20-0x2f)* + final (0x30-0x7e), e.g. charset selection
    local j = i + 1
    while true do
      local c = s:byte(j)
      if c == nil or (c >= 0x30 and c <= 0x7e) then
        return j - i + 1
      end
      j = j + 1
    end
  end
end

---@class secrets.AnsiMap
---@field text string the line without escape sequences

---Strip ANSI sequences.
---@param line string
---@return secrets.AnsiMap
function M.strip(line)
  if not line:find("\27", 1, true) then
    return { text = line }
  end
  local out, i = {}, 1
  while i <= #line do
    local len = escape_length(line, i)
    if len then
      i = i + len
    else
      table.insert(out, line:sub(i, i))
      i = i + 1
    end
  end
  return { text = table.concat(out) }
end

---Replace visible spans of a possibly coloured line with mask characters, keeping escapes.
---@param line string
---@param spans { [1]: integer, [2]: integer }[] 0-based byte spans into the stripped text
---@param mask fun(s: string): string
---@return string
function M.mask(line, spans, mask)
  local stripped = M.strip(line)
  local visible = stripped.text
  local out, vpos, si = {}, 0, 1
  local i = 1
  while i <= #line do
    local len = escape_length(line, i)
    if len then
      table.insert(out, line:sub(i, i + len - 1))
      i = i + len
    else
      while si <= #spans and vpos >= spans[si][2] do
        si = si + 1
      end
      local span = spans[si]
      if span and vpos >= span[1] then
        if vpos == span[1] then
          table.insert(out, mask(visible:sub(span[1] + 1, span[2])))
        end
      else
        table.insert(out, line:sub(i, i))
      end
      vpos = vpos + 1
      i = i + 1
    end
  end
  return table.concat(out)
end

return M
