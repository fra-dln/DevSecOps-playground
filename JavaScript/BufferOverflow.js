const readline = require('readline');
const { promisify } = require('util');
const { createReadStream } = require('fs');
const { Buffer } = require('buffer');

const MAX_SIZE = 256; // You can change the value as needed

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const readAsync = promisify(createReadStream(process.stdin.fd).read);

async function main() {
  const buf = Buffer.alloc(64);
  const inBuffer = Buffer.alloc(MAX_SIZE);

  console.log("Enter buffer contents:");
  const bytesRead = await readAsync(inBuffer, 0, MAX_SIZE - 1);

  if (bytesRead === null) {
    console.error("Error reading input.");
    process.exit(1);
  }

  const input = inBuffer.toString('utf8', 0, bytesRead);

  console.log("Bytes to copy:");
  rl.question('', (bytesInput) => {
    const bytes = parseInt(bytesInput);

    if (isNaN(bytes) || bytes < 0 || bytes >= MAX_SIZE) {
      console.error("Invalid input for 'bytes'. Please enter a valid number.");
      process.exit(1);
    }

    if (bytes > bytesRead) {
      console.error("Error: 'bytes' is greater than the input buffer size.");
      process.exit(1);
    }

    input.copy(buf, 0, 0, bytes);
    console.log(`Copied ${bytes} bytes to 'buf':\n${buf.toString('utf8', 0, bytes)}`);
    rl.close();
  });
}

main();
