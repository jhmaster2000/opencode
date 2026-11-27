import fs from "node:fs/promises"
import path from "node:path"
import { tmpdir } from "../test/fixture/tmpdir"

// Require a working backend and run the shared suite alongside this host's regressions.
const backendSuites: Partial<Record<NodeJS.Platform, string>> = {
  darwin: "test/sandbox-macos.test.ts",
  linux: "test/sandbox-linux.test.ts",
}
const localSuite = backendSuites[process.platform]
if (!localSuite) throw new Error(`No sandbox enforcement suite for ${process.platform}`)
const nativeSuites = Object.values(backendSuites)

await using temporary = await tmpdir("opencode-sandbox-validation-")
const report = path.join(temporary.path, "results.xml")
const files = (await Array.fromAsync(new Bun.Glob("test/sandbox-*.test.ts").scan({ cwd: process.cwd() })))
  .filter((file) => file === localSuite || !nativeSuites.includes(file))
  .sort()
if (files.length === 0) throw new Error("Run sandbox validation from packages/core")
const child = Bun.spawn(
  [process.execPath, "run", "script/test.ts", ...files, "--reporter=junit", `--reporter-outfile=${report}`],
  {
    env: { ...process.env, OPENCODE_SANDBOX_TEST_REQUIRED: "1" },
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  },
)
const interrupt = () => child.kill("SIGINT")
const terminate = () => child.kill("SIGTERM")
process.once("SIGINT", interrupt)
process.once("SIGTERM", terminate)
const code = await child.exited
process.off("SIGINT", interrupt)
process.off("SIGTERM", terminate)
if (code !== 0) process.exitCode = code
else {
  const xml = await fs.readFile(report, "utf8")
  const suites = [...xml.matchAll(/<testsuite\b[^>]*\bskipped="(\d+)"/g)]
  if (suites.length === 0 || suites.some((suite) => Number(suite[1]) !== 0))
    throw new Error(
      "Incomplete sandbox enforcement run: skipped tests or missing results. Provision the tested runtimes and run on a supported host.",
    )
  console.log("Sandbox enforcement validation passed without skips.")
}
