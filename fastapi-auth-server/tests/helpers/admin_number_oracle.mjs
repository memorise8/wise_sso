import fs from "node:fs";

const corpus = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const cases = corpus.cases.map(({ input }) => {
  const value = Number(input);
  const accepted = Number.isFinite(value) && Number.isInteger(value);
  return {input, accepted, integer: accepted ? value.toFixed(0) : null};
});

process.stdout.write(`${JSON.stringify({cases})}\n`);
