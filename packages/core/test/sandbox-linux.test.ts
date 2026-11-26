import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import path from "node:path"
import { LinuxSandbox } from "../src/sandbox/linux"
import { SandboxHostPolicy } from "../src/sandbox/host-policy"
import { SandboxFileWorker } from "../src/sandbox/file-worker"
import { SandboxPolicy } from "../src/sandbox/policy"
import { tmpdir } from "./fixture/tmpdir"

const native = test.skipIf(process.platform !== "linux" || process.env.OPENCODE_LINUX_SANDBOX_TEST !== "1")

native.each([false, true])(
  "Bubblewrap enforces file, process and network policy with fullDiskRead=%s",
  async (fullDiskRead) => {
    await using temporary = await tmpdir()
    const root = await fs.realpath(temporary.path)
    const host = {
      directory: path.join(root, "workspace"),
      scratch: path.join(root, "scratch"),
      home: path.join(root, "home"),
      config: path.join(root, "config"),
      data: path.join(root, "data"),
      state: path.join(root, "state"),
    }
    await Promise.all(Object.values(host).map((directory) => fs.mkdir(directory)))
    const nested = path.join(host.directory, "nested")
    await fs.mkdir(path.join(nested, ".git"), { recursive: true })
    await fs.writeFile(path.join(nested, ".git", "config"), "git-canary")
    await fs.writeFile(path.join(host.config, "private"), "config-canary")
    const outside = path.join(root, "outside")
    await fs.writeFile(outside, "outside-canary")
    const backend = await LinuxSandbox.backend()
    const policy = await backend.policy(host, { fullDiskRead })
    const run = async (script: string, input = policy, env = process.env) => {
      const launch = await backend.launch(
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
    expect((await run(`cat '${host.config}/private'`)).exitCode).not.toBe(0)
    expect((await run("echo blocked > .git/config")).exitCode).not.toBe(0)
    expect((await run(`echo blocked > '${host.directory}/opencode.json'`)).exitCode).not.toBe(0)
    expect((await run(`test ! -e /proc/${process.pid}/cmdline`)).exitCode).toBe(0)
    expect(await fs.readFile(outside, "utf8")).toBe("outside-canary")
    // A broad read can stack fresh procfs over a host mount. Resolve the
    // effective mount via the descriptor instead of counting hidden layers.
    for (const target of ["/proc", "/proc/sys", "/proc/sys/kernel/core_pattern"]) {
      const mounted = await run(`exec 8<'${target}'; cat /proc/self/fdinfo/8 /proc/self/mountinfo`)
      expect(mounted.exitCode).toBe(0)
      const info = mounted.stdout.toString()
      const id = /^mnt_id:\s*(\d+)$/m.exec(info)?.[1]
      expect(id).toBeDefined()
      const mount = info.split("\n").find((line) => line.startsWith(`${id} `))
      expect({ target, mount, readonly: mount?.split(" ")[5].split(",").includes("ro") }).toMatchObject({
        readonly: true,
      })
    }

    await fs.mkdir(path.join(host.data, "repos"))
    await fs.writeFile(path.join(host.data, "repos", "public.txt"), "reference-canary")
    await fs.writeFile(path.join(host.data, "auth.json"), "secret-canary")
    const referenced = await SandboxHostPolicy.references(policy, host, [host.data])
    expect((await run(`cat '${host.data}/repos/public.txt'`, referenced)).stdout.toString()).toBe("reference-canary")
    expect((await run(`cat '${host.data}/auth.json'`, referenced)).exitCode).not.toBe(0)

    const gitWrites = await backend.policy(host, { fullDiskRead, allowGitWrites: true })
    expect((await run("echo allowed > .git/config", gitWrites)).exitCode).toBe(0)

    const runtime = await fs.realpath(process.execPath)
    const worker = await backend.fileLaunch(policy, runtime, SandboxFileWorker.configured(policy))
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

native("Bubblewrap blocks connections to host sockets", async () => {
  await using temporary = await tmpdir()
  const root = await fs.realpath(temporary.path)
  const host = {
    directory: path.join(root, "workspace"),
    scratch: path.join(root, "scratch"),
    home: path.join(root, "home"),
    config: path.join(root, "config"),
    data: path.join(root, "data"),
    state: path.join(root, "state"),
  }
  await Promise.all(Object.values(host).map((directory) => fs.mkdir(directory)))
  const socket = path.join(host.directory, "http.sock")
  const tcp = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response("host") })
  const unix = Bun.serve({ unix: socket, fetch: () => new Response("host") })
  try {
    const backend = await LinuxSandbox.backend()
    const curl = Bun.which("curl")
    if (!curl) throw new Error("Install curl for Linux sandbox validation")
    const policy = await backend.policy(host, {})
    for (const destination of [[`http://127.0.0.1:${tcp.port}`], ["--unix-socket", socket, "http://localhost"]]) {
      const args = ["--fail", "--silent", "--show-error", "--noproxy", "*", "--max-time", "2", ...destination]
      const spawn = async (command: string, args: readonly string[], env?: SandboxPolicy.Launch["env"]) => {
        const child = Bun.spawn([command, ...args], { cwd: host.directory, env, stdout: "pipe", stderr: "ignore" })
        return { exit: await child.exited, output: await new Response(child.stdout).text() }
      }
      expect(await spawn(curl, args)).toEqual({ exit: 0, output: "host" })
      const launch = await backend.launch(policy, curl, args, SandboxPolicy.environment(process.env, host.scratch))
      expect((await spawn(launch.command, launch.args, launch.env)).exit).not.toBe(0)
    }
  } finally {
    tcp.stop(true)
    unix.stop(true)
  }
})
