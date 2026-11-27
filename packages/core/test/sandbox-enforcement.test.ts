import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { SandboxHostPolicy } from "../src/sandbox/host-policy"
import { SandboxFileWorker } from "../src/sandbox/file-worker"
import { SandboxPolicy } from "../src/sandbox/policy"
import { tmpdir } from "./fixture/tmpdir"
import { nativeSandbox, sandboxHost } from "./fixture/sandbox-host"

const backend = await nativeSandbox()
const native = test.skipIf(!backend)

native.each([false, true])(
  "The sandbox enforces file and process policy with fullDiskRead=%s",
  async (fullDiskRead) => {
    await using temporary = await tmpdir()
    const root = temporary.path
    const host = await sandboxHost(root)
    const nested = path.join(host.directory, "nested")
    await fs.mkdir(path.join(nested, ".git"), { recursive: true })
    await fs.writeFile(path.join(nested, ".git", "config"), "git-canary")
    await fs.writeFile(path.join(host.directory, "opencode.json"), "{}")
    await fs.writeFile(path.join(host.config, "private"), "config-canary")
    const submodule = path.join(host.directory, "submodule")
    const extra = path.join(root, "extra")
    await fs.mkdir(submodule)
    await fs.mkdir(path.join(extra, ".git"), { recursive: true })
    const submoduleGit = path.join(submodule, ".git")
    await fs.writeFile(submoduleGit, "gitdir: ../.git/modules/submodule")
    const readOnly = path.join(host.directory, "read-only")
    await fs.mkdir(readOnly)
    await fs.writeFile(path.join(readOnly, "file"), "read-only-canary")
    const database = path.join(host.directory, "state.db")
    await fs.writeFile(database, "database-canary")
    await fs.writeFile(database + "-wal", "wal-canary")
    const outside = path.join(root, "outside")
    await fs.writeFile(outside, "outside-canary")
    const policy = await backend!.policy(host, { fullDiskRead, readableRoots: [readOnly] }, [], database)
    const run = async (script: string, input = policy, env = process.env) => {
      const launch = await backend!.launch(
        input,
        "/bin/sh",
        ["-c", script],
        SandboxPolicy.environment(env, host.scratch),
        nested,
      )
      return Bun.spawnSync([launch.command, ...launch.args], { cwd: nested, env: launch.env, timeout: 10_000 })
    }
    const positive = await run("printf local > result; cat result")
    expect(positive.stderr.toString()).toBe("")
    expect(positive.exitCode).toBe(0)
    expect(positive.stdout.toString()).toBe("local")
    expect(await fs.readFile(path.join(nested, "result"), "utf8")).toBe("local")
    expect((await run(`cat '${outside}'`)).exitCode === 0).toBe(fullDiskRead)
    expect((await run(`echo blocked > '${outside}'`)).exitCode).not.toBe(0)
    expect(await fs.readFile(outside, "utf8")).toBe("outside-canary")
    expect((await run(`cat '${host.config}/private'`)).exitCode).not.toBe(0)
    expect((await run("echo blocked > .git/config")).exitCode).not.toBe(0)
    expect((await run(`echo blocked > '${submoduleGit}'`)).exitCode).not.toBe(0)
    expect((await run("echo allowed > .gitignore")).exitCode).toBe(0)
    expect((await run(`echo blocked > '${host.directory}/opencode.json'`)).exitCode).not.toBe(0)

    expect((await run(`cat '${readOnly}/file'`)).stdout.toString()).toBe("read-only-canary")
    expect((await run(`printf denied > '${readOnly}/file'`)).exitCode).not.toBe(0)
    for (const file of [database, database + "-wal"]) {
      expect((await run(`cat '${file}'`)).exitCode).not.toBe(0)
      expect((await run(`printf denied > '${file}'`)).exitCode).not.toBe(0)
    }
    expect((await run('printf scratch > "$TMPDIR/probe"')).exitCode).toBe(0)

    const gitWrites = await backend!.policy(host, { fullDiskRead, allowGitWrites: true, writableRoots: [extra] })
    expect((await run("echo allowed > .git/config", gitWrites)).exitCode).toBe(0)
    expect((await run(`echo allowed > '${submoduleGit}'`, gitWrites)).exitCode).toBe(0)
    expect((await run(`echo blocked > '${extra}/.git/index'`, gitWrites)).exitCode).not.toBe(0)

    const runtime = await fs.realpath(process.execPath)
    const worker = await backend!.fileLaunch(policy, runtime, SandboxFileWorker.configured(policy))
    const result = Bun.spawn([worker.command, ...worker.args], {
      cwd: policy.scratch,
      env: worker.env,
      stdin: Buffer.from(JSON.stringify({ op: "read", path: path.join(nested, "result") })),
      stdout: "pipe",
      stderr: "pipe",
      timeout: 10_000,
    })
    const [code, stdout, stderr] = await Promise.all([
      result.exited,
      new Response(result.stdout).text(),
      new Response(result.stderr).text(),
    ])
    expect(stderr).toBe("")
    expect(code).toBe(0)
    expect(JSON.parse(stdout)).toMatchObject({
      op: "read",
      data: Buffer.from("local").toString("base64"),
    })
  },
)

native.each([false, true])(
  "the sandbox blocks connections to host sockets with fullDiskRead=%s",
  async (fullDiskRead) => {
    await using temporary = await tmpdir("oc-net-")
    const host = await sandboxHost(temporary.path)
    const socket = path.join(host.directory, "s")
    const tcp = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("host") })
    const unix = Bun.serve({ unix: socket, fetch: () => new Response("host") })
    try {
      const curl = Bun.which("curl")
      if (!curl) throw new Error("Install curl for sandbox validation")
      const policy = await backend!.policy(host, { fullDiskRead })
      for (const destination of [[`http://127.0.0.1:${tcp.port}`], ["--unix-socket", socket, "http://localhost"]]) {
        const args = ["--fail", "--silent", "--show-error", "--noproxy", "*", "--max-time", "2", ...destination]
        const spawn = async (command: string, args: readonly string[], env?: SandboxPolicy.Launch["env"]) => {
          const child = Bun.spawn([command, ...args], { cwd: host.directory, env, stdout: "pipe", stderr: "ignore" })
          return { exit: await child.exited, output: await new Response(child.stdout).text() }
        }
        expect(await spawn(curl, args)).toEqual({ exit: 0, output: "host" })
        const launch = await backend!.launch(policy, curl, args, SandboxPolicy.environment(process.env, host.scratch))
        expect((await spawn(launch.command, launch.args, launch.env)).exit).not.toBe(0)
      }
    } finally {
      tcp.stop(true)
      unix.stop(true)
    }
  },
)

native.each([false, true])(
  "reference grants in OpenCode data preserve private files with fullDiskRead=%s",
  async (fullDiskRead) => {
    const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-reference-policy-")))
    try {
      const host = {
        directory: path.join(root, "workspace"),
        scratch: path.join(root, "scratch"),
        home: path.join(root, "home"),
        config: path.join(root, "config"),
        data: path.join(root, "data (test)"),
        state: path.join(root, "state"),
      }
      await Promise.all(Object.values(host).map((value) => fs.mkdir(value)))
      await fs.mkdir(path.join(host.data, "repos"))
      await fs.mkdir(path.join(host.data, "log"))
      await fs.writeFile(path.join(host.data, "repos", "readme"), "reference-public")
      const authTarget = path.join(root, "auth-target")
      await fs.writeFile(authTarget, "auth-secret")
      await fs.symlink(authTarget, path.join(host.data, "auth.json"))
      await fs.writeFile(path.join(host.data, "opencode.db"), "db-secret")
      await fs.writeFile(path.join(host.data, "opencode.db-wal"), "wal-secret")
      await fs.writeFile(path.join(host.data, "log", "log.txt"), "log-secret")
      await fs.writeFile(path.join(host.config, "settings"), "config-secret")
      const credentials = path.join(host.home, ".ssh")
      await fs.mkdir(credentials)
      await fs.writeFile(path.join(credentials, "key"), "ssh-secret")
      const base = await backend!.policy(host, { fullDiskRead })
      const confined = await SandboxHostPolicy.references(base, host, [host.data, host.config, credentials])
      // The pattern protects database files created after the profile was prepared.
      await fs.writeFile(path.join(host.data, "opencode-new.db-shm"), "shm-secret")
      await fs.writeFile(path.join(host.data, "OPENCODE-NEW.DB-JOURNAL"), "journal-secret")
      const run = async (command: string) => {
        const launch = await backend!.launch(
          confined,
          "/bin/sh",
          ["-c", command],
          SandboxPolicy.environment(process.env, host.scratch),
        )
        return Bun.spawnSync([launch.command, ...launch.args], { cwd: host.directory, env: launch.env })
      }
      expect((await run(`cat '${host.data}/repos/readme'`)).stdout.toString()).toBe("reference-public")
      expect((await run(`ls '${host.data}'`)).exitCode).toBe(0)
      for (const target of [
        path.join(host.data, "auth.json"),
        authTarget,
        path.join(host.data, "opencode.db"),
        path.join(host.data, "opencode.db-wal"),
        path.join(host.data, "opencode-new.db-shm"),
        path.join(host.data, "OPENCODE-NEW.DB-JOURNAL"),
        path.join(host.data, "log", "log.txt"),
        path.join(host.config, "settings"),
        path.join(credentials, "key"),
      ]) {
        expect((await run(`cat '${target}'`)).exitCode).not.toBe(0)
      }
      expect((await run(`printf escape > '${host.data}/repos/new'`)).exitCode).not.toBe(0)
    } finally {
      await fs.rm(root, { recursive: true, force: true })
    }
  },
)
const python = Bun.which("python3")
test.skipIf(!backend || !python)("broad reads let Python load its runtime and urllib without extra roots", async () => {
  if (!python) throw new Error("Python is unavailable")
  await using temporary = await tmpdir()
  const host = await sandboxHost(temporary.path)
  const policy = await backend!.policy(host, { fullDiskRead: true })
  const launch = await backend!.launch(
    policy,
    python,
    ["-I", "-B", "-c", 'import ssl, urllib.request; print("runtime ready")'],
    SandboxPolicy.environment(process.env, host.scratch),
  )
  const result = Bun.spawnSync([launch.command, ...launch.args], { cwd: host.directory, env: launch.env })
  expect({ exit: result.exitCode, stderr: result.stderr.toString() }).toMatchObject({ exit: 0 })
  expect(result.stdout.toString()).toBe("runtime ready\n")
})
