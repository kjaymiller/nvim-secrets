-- Entry point for bin/rg-secrets: nvim --clean -l bin/rg-secrets.lua [args]
local root = vim.fs.dirname(vim.fs.dirname(debug.getinfo(1, "S").source:sub(2)))
vim.opt.rtp:prepend(root)
-- `arg` from `nvim -l` has a [0] entry (the script path); copy only the 1-based list so the CLI
-- front end gets a plain array. A user's own `--` separator is kept.
local argv = {}
for i = 1, #arg do
  argv[i] = arg[i]
end
os.exit(require("secrets.rg").main(argv))
