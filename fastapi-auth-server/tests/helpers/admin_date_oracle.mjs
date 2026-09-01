import fs from "node:fs";

const corpus = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const results = corpus.cases.map(({ input }) => {
  const epoch = Date.parse(input);
  return {
    input,
    iso: Number.isNaN(epoch) ? null : new Date(epoch).toISOString()
  };
});

process.stdout.write(`${JSON.stringify({
  processTimezone: process.env.TZ ?? null,
  cases: results
})}\n`);
