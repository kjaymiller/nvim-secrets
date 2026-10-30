if vim.g.loaded_secrets then
  return
end
vim.g.loaded_secrets = true

local function cmd(name, fn, desc)
  vim.api.nvim_create_user_command(name, function()
    require("secrets")[fn]()
  end, { desc = desc })
end

cmd("SecretsEnable", "enable", "Mask secrets")
cmd("SecretsDisable", "disable", "Stop masking secrets")
cmd("SecretsToggle", "toggle", "Toggle secret masking")
cmd("SecretsToggleBuffer", "toggle_buffer", "Toggle secret masking for this buffer")
