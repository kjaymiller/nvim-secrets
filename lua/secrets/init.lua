local detect = require("secrets.detect")
local scanners = require("secrets.scanners")

local M = {}

local defaults = {
  enabled = true,
  mask_char = "•",
  hl_group = "Comment",
  reveal_cursorline = false, -- show the real text on the cursor line
  reveal_modes = { "i", "R" }, -- first character of vim.fn.mode() that shows the real text
  backends = { "lua" }, -- any of "lua", "ripsecrets", "betterleaks"
  commands = {}, -- override executables, e.g. { betterleaks = "/opt/bin/betterleaks" }
  scan_delay = 150, -- ms to wait after a change before running an external scanner
  entropy = true, -- also flag high-entropy quoted strings (lua backend)
  entropy_threshold = 4.0,
  max_lines = 20000, -- skip private-key scanning above this many lines
  disabled_filetypes = {},
}

local config = vim.deepcopy(defaults)
local ns = vim.api.nvim_create_namespace("secrets")
local disabled_bufs = {}
local key_cache = {} -- bufnr -> { tick, lines }
local results = {} -- bufnr -> scanner name -> secrets it reported
local found = {} -- bufnr -> every secret reported by any scanner
local timers = {} -- bufnr -> debounce timer
local warned = {}

local function use_lua()
  return vim.tbl_contains(config.backends, "lua")
end

local function external()
  return vim.tbl_filter(function(name)
    return scanners.defs[name] ~= nil
  end, config.backends)
end

local function redraw()
  vim.cmd("redraw!")
end

local function key_lines(buf)
  local tick = vim.api.nvim_buf_get_changedtick(buf)
  local cached = key_cache[buf]
  if cached and cached.tick == tick then
    return cached.lines
  end
  local lines = {}
  if vim.api.nvim_buf_line_count(buf) <= config.max_lines then
    lines = detect.private_key_lines(vim.api.nvim_buf_get_lines(buf, 0, -1, false))
  end
  key_cache[buf] = { tick = tick, lines = lines }
  return lines
end

local function revealing()
  return vim.tbl_contains(config.reveal_modes, vim.api.nvim_get_mode().mode:sub(1, 1))
end

local function active(buf)
  return config.enabled
    and not revealing()
    and not disabled_bufs[buf]
    and not vim.tbl_contains(config.disabled_filetypes, vim.bo[buf].filetype)
end

local function scan(buf)
  if not active(buf) or vim.bo[buf].buftype ~= "" then
    return
  end
  for _, name in ipairs(external()) do
    local cmd = config.commands[name] or scanners.defs[name].cmd
    if vim.fn.executable(cmd) == 0 then
      if not warned[name] then
        warned[name] = true
        vim.notify(("secrets.nvim: `%s` not found, skipping it"):format(cmd), vim.log.levels.WARN)
      end
    else
      scanners.scan(name, buf, cmd, function(secrets)
        results[buf] = results[buf] or {}
        results[buf][name] = secrets
        found[buf] = vim.fn.uniq(vim.fn.sort(vim.iter(vim.tbl_values(results[buf])):flatten():totable()))
        redraw()
      end)
    end
  end
end

local function schedule_scan(buf)
  if timers[buf] then
    timers[buf]:stop()
  else
    timers[buf] = assert(vim.uv.new_timer())
  end
  timers[buf]:start(config.scan_delay, 0, vim.schedule_wrap(function()
    if vim.api.nvim_buf_is_valid(buf) then
      scan(buf)
    end
  end))
end

local function mask(text)
  return string.rep(config.mask_char, vim.fn.strdisplaywidth(text))
end

local function setup_provider()
  vim.api.nvim_set_decoration_provider(ns, {
    on_win = function(_, _, buf)
      return active(buf)
    end,
    on_line = function(_, win, buf, row)
      if config.reveal_cursorline and win == vim.api.nvim_get_current_win() then
        if vim.api.nvim_win_get_cursor(win)[1] - 1 == row then
          return
        end
      end
      local line = vim.api.nvim_buf_get_lines(buf, row, row + 1, false)[1] or ""
      local spans
      if key_lines(buf)[row] then
        spans = { { 0, #line } }
      else
        spans = use_lua() and detect.find(line, config) or {}
        if found[buf] then
          vim.list_extend(spans, detect.find_literals(line, found[buf]))
          spans = detect.merge(spans)
        end
      end
      for _, span in ipairs(spans) do
        vim.api.nvim_buf_set_extmark(buf, ns, row, span[1], {
          virt_text = { { mask(line:sub(span[1] + 1, span[2])), config.hl_group } },
          virt_text_pos = "overlay",
          hl_mode = "replace",
          ephemeral = true,
        })
      end
    end,
  })
end

---@param opts? table overrides for the defaults above
function M.setup(opts)
  config = vim.tbl_deep_extend("force", defaults, opts or {})
  setup_provider()
  local group = vim.api.nvim_create_augroup("secrets", { clear = true })
  vim.api.nvim_create_autocmd("ModeChanged", {
    group = group,
    callback = function()
      -- repaint only when crossing the reveal boundary
      local old, new = vim.v.event.old_mode:sub(1, 1), vim.v.event.new_mode:sub(1, 1)
      if vim.tbl_contains(config.reveal_modes, old) ~= vim.tbl_contains(config.reveal_modes, new) then
        redraw()
      end
    end,
  })
  vim.api.nvim_create_autocmd({ "BufEnter", "TextChanged", "InsertLeave" }, {
    group = group,
    callback = function(args)
      schedule_scan(args.buf)
    end,
  })
  vim.api.nvim_create_autocmd("BufWipeout", {
    group = group,
    callback = function(args)
      key_cache[args.buf] = nil
      found[args.buf] = nil
      results[args.buf] = nil
      for name in pairs(scanners.defs) do
        scanners.stop(name, args.buf)
      end
      if timers[args.buf] then
        timers[args.buf]:close()
        timers[args.buf] = nil
      end
      disabled_bufs[args.buf] = nil
    end,
  })
  redraw()
end

function M.enable()
  config.enabled = true
  disabled_bufs[vim.api.nvim_get_current_buf()] = nil
  redraw()
end

function M.disable()
  config.enabled = false
  redraw()
end

function M.toggle()
  config.enabled = not config.enabled
  redraw()
end

---Toggle masking for the current buffer only.
function M.toggle_buffer()
  local buf = vim.api.nvim_get_current_buf()
  disabled_bufs[buf] = not disabled_bufs[buf] or nil
  redraw()
end

return M
