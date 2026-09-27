import { readFileSync } from "node:fs";
import { verifyPacket } from "../src/helpers/receiptIntegrity.mjs";
if (!process.argv[2]) {
  console.error("Usage: npm run verify -- path/to/exported-packet.json");
  process.exitCode = 2;
} else {
  try {
    const result = verifyPacket(
      JSON.parse(readFileSync(process.argv[2], "utf8")),
    );
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.valid ? 0 : 1;
  } catch {
    console.error("Could not read a valid JSON evidence packet.");
    process.exitCode = 1;
  }
}
