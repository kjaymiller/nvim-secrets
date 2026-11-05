-- Entry point for bin/rg-secrets: nvim --clean -l bin/rg-secrets.lua [args]
local root = vim.fs.dirname(vim.fs.dirname(debug.getinfo(1, "S").source:sub(2)))
vim.opt.rtp:prepend(root)
os.exit(require("secrets.rg").main(arg))
