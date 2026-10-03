#!/usr/bin/env node
import { Command } from "commander";
import { readFile, writeFile, access } from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import readline from "node:readline";

const program = new Command();

const VERSION = "1";
const ALGO = "aes-256-gcm";
const KEY_LEN = 32;
const IV_LEN = 12;
const SALT_LEN = 16;
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}

function unb64(str) {
  return Buffer.from(str, "base64");
}

function deriveKey(password, salt) {
  return crypto.scryptSync(password, salt, KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 128 * 1024 * 1024
  });
}

function encryptString(plainText, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = deriveKey(password, salt);

  const cipher = crypto.createCipheriv(ALGO, key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plainText, "utf8"),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return {
    v: VERSION,
    alg: ALGO,
    kdf: {
      name: "scrypt",
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      salt: b64(salt)
    },
    iv: b64(iv),
    tag: b64(tag),
    ct: b64(ciphertext)
  };
}

function decryptObject(payload, password) {
  if (!payload || payload.v !== VERSION || payload.alg !== ALGO || payload.kdf?.name !== "scrypt") {
    throw new Error("Unsupported encrypted payload format");
  }

  const salt = unb64(payload.kdf.salt);
  const iv = unb64(payload.iv);
  const tag = unb64(payload.tag);
  const ct = unb64(payload.ct);

  const key = crypto.scryptSync(password, salt, KEY_LEN, {
    N: payload.kdf.N,
    r: payload.kdf.r,
    p: payload.kdf.p,
    maxmem: 128 * 1024 * 1024
  });

  const decipher = crypto.createDecipheriv(ALGO, key, iv);
  decipher.setAuthTag(tag);

  const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  return plain.toString("utf8");
}

// cmd.exe keeps surrounding quotes in argv while bash/PowerShell strip them, so strip them here to keep passwords identical across shells.
function normalizePassword(raw) {
  const wrapped =
    raw.length > 1 &&
    ((raw.startsWith("'") && raw.endsWith("'")) || (raw.startsWith('"') && raw.endsWith('"')));
  return wrapped ? raw.slice(1, -1) : raw;
}

async function fileExists(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function promptHidden(query) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true
    });

    rl.question(query, { hideEchoBack: true }, (answer) => {
      rl.close();
      console.log();
      resolve(answer);
    });
  });
}

async function resolvePassword(cliPassword, decryptMode) {
  if (cliPassword) {
    return normalizePassword(cliPassword);
  }

  if (process.env.ENVSEAL_PASS) {
    return normalizePassword(process.env.ENVSEAL_PASS);
  }

  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("Password is required. Provide --pass, set ENVSEAL_PASS, or run in an interactive terminal.");
  }

  const password = await promptHidden("Enter password: ");

  if (!password) {
    throw new Error("Password cannot be empty.");
  }

  if (decryptMode) {
    return password;
  }

  const confirmation = await promptHidden("Confirm password: ");

  if (password !== confirmation) {
    throw new Error("Passwords did not match.");
  }

  return password;
}

program
  .name("envseal")
  .description("Encrypt/decrypt .env files for safe git transfer")
  .option("--pass <password>", "Master password (prefer interactive prompt for local use; wrap in single quotes '...' in bash to avoid '!' history expansion)")
  .option("--in <path>", "Input file path", ".env")
  .option("--out <path>", "Output file path")
  .option("--decrypt", "Decrypt mode")
  .option("--force", "Overwrite output if it exists", false)
  .addHelpText(
    "after",
    "\nNote on special characters in bash:\n  If your password contains '!', wrap it in single quotes (e.g. --pass 'pass!123').\n  In double quotes, bash treats '!' as history expansion and fails before the CLI runs.\n"
  )
  .parse(process.argv);

const opts = program.opts();
const decryptMode = Boolean(opts.decrypt);
const inputPath = opts.in;
const outputPath = opts.out || (decryptMode ? ".env" : ".env.enc");

let password;

try {
  password = await resolvePassword(opts.pass, decryptMode);
} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(1);
}

if (path.resolve(inputPath) === path.resolve(outputPath)) {
  console.error("Error: Input and output paths must be different to avoid overwriting the source file.");
  process.exit(1);
}

if (!opts.force && await fileExists(outputPath)) {
  console.error(`Error: Output file already exists: ${outputPath}. Use --force to overwrite.`);
  process.exit(1);
}

try {
  const input = await readFile(inputPath, "utf8");

  if (!decryptMode) {
    const encrypted = encryptString(input, password);
    await writeFile(outputPath, JSON.stringify(encrypted, null, 2) + "\n", "utf8");
    console.log(`Encrypted ${inputPath} -> ${outputPath}`);
  } else {
    let payload;
    try {
      payload = JSON.parse(input);
    } catch {
      throw new Error(`Input file is not valid encrypted JSON. Did you mean --in .env.enc? (got: ${inputPath})`);
    }

    const decrypted = decryptObject(payload, password);

    await writeFile(outputPath, decrypted, "utf8");
    console.log(`Decrypted ${inputPath} -> ${outputPath}`);
  }
} catch (err) {
  console.error(`Failed: ${err.message}`);
  process.exit(1);
}