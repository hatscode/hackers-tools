const { spawn } = require("child_process");
const input = process.argv[2];

console.log(`Running: ${input}`);
const proc = spawn(input, [], { stdio: "inherit", shell: false });
