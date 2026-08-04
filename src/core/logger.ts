import { Console } from 'console';

// Create a custom logger that writes to stderr for all standard logging.
// This prevents informational logs from polluting stdout when users
// pipe the JSON output to a file (e.g. \`leetguard scan . -f json > out.json\`).
export const logger = new Console({
  stdout: process.stderr,
  stderr: process.stderr,
});
