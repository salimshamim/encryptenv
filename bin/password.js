import readline from "node:readline";

export function normalizePassword(raw) {
  const wrapped =
    raw.length > 1 &&
    ((raw.startsWith("'") && raw.endsWith("'")) || (raw.startsWith('"') && raw.endsWith('"')));
  return wrapped ? raw.slice(1, -1) : raw;
}

export function promptHidden(
  query,
  {
    input = process.stdin,
    output = process.stdout,
    createInterface = readline.createInterface
  } = {}
) {
  return new Promise((resolve) => {
    const rl = createInterface({
      input,
      output,
      terminal: true
    });

    rl.question(query, { hideEchoBack: true }, (answer) => {
      rl.close();
      console.log();
      resolve(answer);
    });
  });
}

export async function resolvePassword({
  cliPassword,
  envPassword,
  decryptMode,
  isInteractive,
  promptHidden
}) {
  if (cliPassword) {
    return normalizePassword(cliPassword);
  }

  if (envPassword) {
    return normalizePassword(envPassword);
  }

  if (!isInteractive) {
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