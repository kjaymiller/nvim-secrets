-- Example lazy.nvim spec; copy into your plugin specs.
return {
  "kjaymiller/nvim-secrets",
  -- dir = "~/nvim-secrets", -- uncomment to use the local checkout
  event = "VeryLazy",
  opts = {
    backends = { "lua", "betterleaks" },
  },
  keys = {
    { "<leader>us", "<cmd>SecretsToggle<cr>", desc = "Toggle secret masking" },
  },
}
