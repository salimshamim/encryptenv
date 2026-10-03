# envseal
Locally encrypt/decrypt env files using a password.

This is designed to protect `.env` contents from casual disclosure when sharing or committing encrypted files. The security boundary is the password: if the password is weak, reused, or exposed elsewhere, the encrypted file can still be brute-forced offline.

## Install / Run
npx @salimshamim/envseal

By default:
- input: .env
- output: .env.enc

If running interactively, `envseal` prompts for a hidden password. For automation, you can still pass `--pass` or set `ENVSEAL_PASS`.

## Encrypt custom file
npx @salimshamim/envseal --pass 'masterpass' --in .env.local --out .env.local.enc

## Decrypt
npx @salimshamim/envseal --decrypt --pass 'masterpass' --in .env.enc --out .env

## Overwrite output
npx @salimshamim/envseal --pass 'masterpass' --force

`--force` allows replacing an existing output file, but input and output paths must still be different to avoid destroying the source file.

## Environment Variable
You can also supply your password via `ENVSEAL_PASS`:
```bash
export ENVSEAL_PASS='masterpass'
npx @salimshamim/envseal
npx @salimshamim/envseal --decrypt --in .env.enc --out .env
```

## Security Notes
- The encrypted file intentionally stores metadata like algorithm, salt, IV, and authentication tag. Those values are not secrets.
- The password is the secret. Use a strong, unique password with high entropy.
- Anyone who obtains `.env.enc` can attempt offline password guessing; `scrypt` raises the cost but does not make weak passwords safe.
- Prefer the interactive prompt or `ENVSEAL_PASS` for local use. Command-line arguments can be exposed via shell history or process inspection.

## Note on Special Characters in Bash (`!`)
If your password contains `!`, always wrap it in **single quotes** (`'...'`) in bash/zsh:
```bash
npx @salimshamim/envseal --pass 'my!secret@1'
```
> **Why?** In interactive bash, `!` inside double quotes (`"..."`) triggers shell history expansion *before* the CLI even starts, leading to `bash: !...: event not found`.

## Cross-Platform Passwords
`--pass 'mypass'` means the same thing on Windows `cmd.exe`, PowerShell, and Linux/macOS bash.

Windows `cmd.exe` does not strip surrounding quotes, so they used to become part of the password and encrypted files failed to decrypt on Linux. envseal now strips a matching pair of surrounding single or double quotes, so you can encrypt on one OS and decrypt on another with the exact same command.

Files encrypted with older versions from `cmd.exe` still decrypt correctly.

## Test
npm test

## Coverage
npm run coverage

## Contribution Guide

### Local setup
```bash
npm install
npm test
npm run coverage
```

### Manual CLI test sequence
1. Create a sample env file:
```bash
printf "API_KEY=abc123\nMODE=dev\n" > .env
```

2. Encrypt it:
```bash
node bin/cli.js
```

3. Decrypt to a different file:
```bash
node bin/cli.js --decrypt --in .env.enc --out .env.dec --pass 'localTest!123'
```

4. Verify round-trip content:
```bash
cat .env.dec
```

Expected result: `.env.dec` should match the original `.env` content exactly.

### Optional: Use environment variable instead of `--pass`
```bash
export ENVSEAL_PASS='localTest!123'
node bin/cli.js
node bin/cli.js --decrypt --in .env.enc --out .env.dec
```

Tip: In bash/zsh, if password contains `!`, always use single quotes (`'...'`).