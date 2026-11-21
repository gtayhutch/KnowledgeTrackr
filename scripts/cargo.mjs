/**
 * Runs a command with the rustup cargo directory on PATH.
 * `cargo` and `worker-build` are installed per user and are not on the
 * default Windows PATH.
 */
import { spawn } from "node:child_process";
import { delimiter, join } from "node:path";
import { homedir } from "node:os";

const cargoBin = join(homedir(), ".cargo", "bin");
const path = [cargoBin, process.env.PATH].filter(Boolean).join(delimiter);
const [command, ...args] = process.argv.slice(2);

if (!command) {
  console.error("usage: node scripts/cargo.mjs <command> [args]");
  process.exit(1);
}

const child = spawn(command, args, {
  env: { ...process.env, PATH: path },
  stdio: "inherit",
  shell: true,
});

child.on("exit", (code) => {
  process.exit(code ?? 1);
});
