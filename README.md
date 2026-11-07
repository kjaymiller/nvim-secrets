# nvim-secrets

![bat-secrets hiding keys](./assets/bat-secrets.png)

Masks secrets and keys in Neovim buffers. Masking is display-only: the buffer text never changes, so yanking and saving still use the real value. Secrets are masked in normal and visual mode. In insert and replace mode only the line under the cursor is shown by default; set `reveal_scope = "all"` to show the whole buffer instead.

It also ships `bat-secrets` and `rg-secrets` commands, so the same detection masks what [bat](https://github.com/sharkdp/bat) and [ripgrep](https://github.com/BurntSushi/ripgrep) print. See [Use with bat](#use-with-bat) and [Use with ripgrep](#use-with-ripgrep).

## What this is not

This plugin hides secrets on screen, for example during a screen share or a recording. It does not stop you leaking secrets in code. Detection is best-effort, a secret can show up before the first scan finishes, and the buffer text and anything you save, yank or commit are untouched.

To keep secrets out of your repos, run the scanners it depends on yourself, such as in a pre-commit hook or in CI:

```sh
ripsecrets                          # scan the working tree
betterleaks dir .                   # scan the working tree
betterleaks git .                   # scan a repo's history
```

## Detection backends

Pick any combination with `backends`:

| Backend       | What it is                                                                                                                          | Runs                       |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| `lua`         | Built-in regexes (known token formats, `key = value` assignments, URI passwords, PEM private keys, entropy check). No dependencies. | Instantly, on every redraw |
| `ripsecrets`  | [ripsecrets](https://github.com/sirwart/ripsecrets). Fast, few false positives, only reports random-looking values.                 | Async, after changes       |
| `betterleaks` | [betterleaks](https://github.com/betterleaks/betterleaks). Large rule set.                                                          | Async, after changes       |

External scanners run on `BufEnter`, `TextChanged` and `InsertLeave`, after `scan_delay` ms. Their findings are masked by value, so every copy of a reported secret is hidden and masks survive edits made before the next scan finishes. A missing binary produces one warning and is skipped.

The plugin never passes `--validate` or `--analyze` to betterleaks, so nothing is sent to a provider. Because ripsecrets can't read stdin, the buffer is written to Neovim's private temp directory for the scan and deleted straight after.

## Custom detection patterns (lua backend)

There are two ways to add your own rules to the lua backend: an editable **rules file**, and a
config list. Both work in the plugin and in `bat-secrets` and `rg-secrets`.

### The rules file

The easiest way is a plain text file. Copy [`patterns.txt`](patterns.txt) from the repo to
`~/.config/nvim/secrets-patterns.txt` and edit it. That file is loaded automatically if it exists.
You can also point at another file with the `patterns_file` option, or `--patterns-file` /
`BAT_SECRETS_PATTERNS_FILE` / `RG_SECRETS_PATTERNS_FILE` on the commands.

The file has one rule per line. Blank lines and lines starting with `#` are ignored. There are
three kinds of rule:

```
# glob: mask anything matching a wildcard pattern
glob acme_*
glob *_secret_*

# keyword: mask the value after `NAME = ` or `NAME: ` (case-insensitive)
keyword RSA_KEY_FILE
keyword signing_key

# regex: a raw Vim "very magic" regex, for anything the other two can't express
#        bracket the part to mask with \zs and \ze
regex \v<myprovider-[A-Za-z0-9]{32}>
```

A line with no keyword prefix is treated as a `glob`, so a file can be just:

```
acme_*
svc_*
```

Glob rules:

- `*` matches any run of characters up to a separator (whitespace, quotes, or one of `` =,:;(){}<>|/ ``).
- `?` matches a single such character.
- Everything else is literal.
- A pattern that starts or ends with a word character is anchored to word boundaries, so `acme_*`
  does not fire inside `xacme_y`. A pattern that ends in `*` or `?` is left open at that end, so
  `key-???` matches a three-character suffix.

Only the part that matches is masked. The usual placeholder guard (`true`, `example`, `$VAR`, ...)
still applies.

### The `patterns` option

For a quick rule, set `patterns` in `setup` (a list of globs, same syntax as `glob` lines). It is
merged with the rules file:

```lua
{
  "kjaymiller/nvim-secrets",
  opts = {
    patterns = { "acme_*", "*_secret_*", "key-??" },
    patterns_file = "~/.config/nvim/secrets-patterns.txt", -- optional; this is the default path
  },
}
```

### How the built-in rules work

If a rule is not expressive enough, the built-in rules live in [`lua/secrets/detect.lua`](lua/secrets/detect.lua) (use `dir = "~/nvim-secrets"` or a fork, see Install). To mask a token with a distinctive prefix, add an entry to `token_patterns`:

```lua
local token_patterns = {
  -- ...
  { name = "acme-token", pat = [=[\v<acme_[A-Za-z0-9]{32}>]=] },
}
```

- `name` is a label for the rule. It isn't used for matching.
- `pat` is a Vim regex, compiled with `vim.regex`. Start it with `\v` for "very magic" syntax, and wrap it in `[=[ ... ]=]` so backslashes need no escaping.
- Everything the pattern matches is masked. To mask only part of a match, bracket it with `\zs` and `\ze`. The built-in `uri-password` rule does this to hide the password and leave the URL readable.
- Use `<` and `>` to anchor word boundaries, so the pattern doesn't fire inside longer strings.

The other rules in the same file:

- `assignment_pat` is built from a keyword list (`secret`, `token`, `password`, `api_key`, `key_file` — so `RSA_KEY_FILE=/path/to/key.pem` is masked — `auth`, `credential`, `private_key`) and masks the value in `secret = value` style lines. A `keyword` rule adds to this list without touching the code.
- `entropy_pat` and the `entropy_threshold` option control the high-entropy string check.
- `placeholders` lists values that are never masked.

Add a case to `tests/detect_spec.lua` and run it:

```lua
check("key = acme_" .. string.rep("aB3d", 8), { "acme_" .. string.rep("aB3d", 8) })
```

```sh
nvim -l tests/detect_spec.lua
nvim --clean -l tests/bat_spec.lua
nvim --clean -l tests/rg_spec.lua
```

If you'd rather not edit Lua, the `ripsecrets` and `betterleaks` backends bring their own rule sets. See each project's docs for custom rules.

## Install

lazy.nvim:

```lua
{
  "kjaymiller/nvim-secrets",
  event = "VeryLazy",
  opts = {
    backends = { "lua", "betterleaks" },
  },
}
```

For local development, use `dir = "~/nvim-secrets"` in place of the repo name.

Install the scanners you want, for example `brew install ripsecrets betterleaks`.

## Use with bat

`bin/bat-secrets` runs bat with secrets masked, using the same `detect.lua` patterns and scanners as the plugin, so a pattern added once works in both. It needs `nvim` and `bat` on your PATH.

```sh
ln -s ~/nvim-secrets/bin/bat-secrets ~/.local/bin/bat-secrets
bat-secrets .env                    # any bat options and files work
echo 'token = abc123def456' | bat-secrets -l ini
alias bat=bat-secrets               # optional
```

bat has no plugin API, so the text is masked before it reaches bat. Highlighting, paging and decorations are unchanged, and the file on disk is never touched. Each secret becomes `mask_char` characters of the same display width, so columns stay aligned. `--version`, `--list-themes` and the other bat modes that don't show files pass straight through.

| Flag                         | Env                         | Default                                                               |
| ---------------------------- | --------------------------- | --------------------------------------------------------------------- |
| `--backends lua,betterleaks` | `BAT_SECRETS_BACKENDS`      | `lua`                                                                 |
| `--mask-char •`              | `BAT_SECRETS_MASK_CHAR`     | `•`                                                                   |
| `--no-entropy`               |                             | entropy check on                                                      |
| `--entropy-threshold 4.0`    |                             | `4.0`                                                                 |
| `--patterns acme_*,svc_*`    | `BAT_SECRETS_PATTERNS`      | none                                                                  |
| `--patterns-file PATH`       | `BAT_SECRETS_PATTERNS_FILE` | none (default `~/.config/nvim/secrets-patterns.txt` if present)      |
| `--reveal`                   | `BAT_SECRETS=0`             | masking on                                                            |
|                              | `BAT_SECRETS_<BACKEND>_CMD` | scanner path, e.g. `BAT_SECRETS_BETTERLEAKS_CMD=/opt/bin/betterleaks` |
|                              | `BAT_SECRETS_BAT`           | `bat`                                                                 |

`bat-secrets --help` (or `-h`, `--secrets-help`) lists them; `--bat-help` shows bat's own help. The scanners run once per file, in the foreground, before bat starts. The plugin's other options (`reveal_*`, `scan_delay`, `disabled_filetypes`) only apply inside Neovim.

## Use with ripgrep

`bin/rg-secrets` runs ripgrep and masks the matches before they are printed, using the same detection as the plugin. It needs `nvim` and `rg` on your PATH.

```sh
ln -s ~/nvim-secrets/bin/rg-secrets ~/.local/bin/rg-secrets
rg-secrets TOKEN file.txt            # any rg options and patterns work
alias rg=rg-secrets                  # optional
```

The output is captured from rg and masked before it is written, so colours, headings, context lines and `--line-number`/`--column` are kept. `--json` is masked too (the redundant base64 `bytes` field is dropped). `--version` and other modes that don't print file contents pass straight through.

| Flag                         | Env                        | Default                                                               |
| ---------------------------- | -------------------------- | --------------------------------------------------------------------- |
| `--backends lua,betterleaks` | `RG_SECRETS_BACKENDS`      | `lua`                                                                 |
| `--mask-char •`              | `RG_SECRETS_MASK_CHAR`     | `•`                                                                   |
| `--no-entropy`               |                            | entropy check on                                                      |
| `--entropy-threshold 4.0`    |                            | `4.0`                                                                 |
| `--patterns acme_*,svc_*`    | `RG_SECRETS_PATTERNS`      | none                                                                  |
| `--patterns-file PATH`       | `RG_SECRETS_PATTERNS_FILE` | none (default `~/.config/nvim/secrets-patterns.txt` if present)      |
| `--reveal`                   | `RG_SECRETS=0`             | masking on                                                            |
|                              | `RG_SECRETS_<BACKEND>_CMD` | scanner path, e.g. `RG_SECRETS_BETTERLEAKS_CMD=/opt/bin/betterleaks`  |
|                              | `RG_SECRETS_RG`            | `rg`                                                                  |

`rg-secrets --help` (or `-h`, `--secrets-help`) lists them; `--rg-help` shows rg's own help. Everything else is passed to rg, so `rg-secrets -- --help` searches for the literal text `--help`.

## Options

```lua
{
  enabled = true,
  mask_char = "•",
  hl_group = "Comment",
  reveal_cursorline = false,  -- show real text on the cursor line
  reveal_modes = { "i", "R" }, -- modes (first character) that show real text
  reveal_scope = "line",      -- "line": cursor line only, "all": whole buffer
  backends = { "lua" },       -- "lua", "ripsecrets", "betterleaks"
  commands = {},              -- e.g. { betterleaks = "/opt/bin/betterleaks" }
  scan_delay = 150,           -- ms after a change before an external scan
  entropy = true,             -- flag high-entropy quoted strings (lua backend)
  entropy_threshold = 4.0,
  patterns = {},              -- custom glob patterns, e.g. { "acme_*", "*_secret_*" }
  patterns_file = nil,        -- rules file (glob/keyword/regex); default: <config>/secrets-patterns.txt
  max_lines = 20000,          -- skip private-key block scanning above this
  disabled_filetypes = {},
}
```

## Commands

- `:SecretsEnable`, `:SecretsDisable`, `:SecretsToggle`
- `:SecretsToggleBuffer` — toggle for the current buffer only

## Limits

- The lua backend masks per line, apart from PEM private key blocks.
- Its entropy check will occasionally flag hashes or IDs.
- Values only get masked by external scanners once the first scan returns.

## Tests

```sh
nvim -l tests/detect_spec.lua
nvim -l tests/ansi_spec.lua
nvim --clean -l tests/bat_spec.lua
nvim --clean -l tests/rg_spec.lua
```
