import { describe, expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { MacSandbox } from "../src/sandbox/macos"
import { SandboxPolicy } from "../src/sandbox/policy"
import { nativeSandbox, hasPosixSandboxFixtures } from "./fixture/sandbox-host"

const policy: SandboxPolicy.Policy = {
  directory: "/private/tmp/project",
  fullDiskRead: false,
  readableRoots: ["/opt/toolchain"],
  writableRoots: ["/private/tmp/project", "/private/tmp/scratch"],
  protectedPaths: ["/private/tmp/project/.opencode"],
  unreadablePaths: ["/private/tmp/project/.aws"],
  scratch: "/private/tmp/scratch",
}

describe("macOS sandbox launch", () => {
  test("full-disk reads leave write, credential, and network restrictions in place", () => {
    const confined = MacSandbox.launch(policy, "/bin/sh", ["-c", "true"], {})
    const expanded = MacSandbox.launch({ ...policy, fullDiskRead: true }, "/bin/sh", ["-c", "true"], {})
    expect(confined.args[1]).not.toContain("(allow file-read* file-map-executable)")
    expect(expanded.args[1]).toContain("(allow file-read* file-map-executable)")
    expect(expanded.args[1]).not.toContain("(allow file-write*)")
    expect(expanded.args[1]).not.toContain("(allow network")
    expect(expanded.args[1]).not.toContain("(allow sysctl-read)")
    expect(expanded.args[1]).not.toContain("(allow sysctl-write")
    expect(expanded.args[1]).toContain('(sysctl-name "hw.ncpu")')
    expect(expanded.args[1]).toContain('(sysctl-name-prefix "hw.optional.")')
    expect(expanded.args[1]).toContain('(sysctl-name-prefix "sysctl.name.")')
    expect(expanded.args[1]).toContain('(sysctl-name-prefix "sysctl.oidfmt.")')
    expect(expanded.args[1]).not.toContain('(sysctl-name-prefix "kern.proc.')
    expect(expanded.args[1]).not.toContain('(sysctl-name-prefix "net.')
    expect(expanded.args[1]).toContain('(allow file-write* (subpath (param "WRITE_0")))')
    expect(expanded.args[1]).toContain('(deny file-write* (subpath (param "PROTECTED_0")))')
    expect(expanded.args[1]).toContain(
      '(deny file-read* file-write* file-map-executable (subpath (param "UNREADABLE_0")))',
    )
    expect(expanded.args.slice(2)).toEqual(confined.args.slice(2))
  })

  test("keeps shell syntax and untrusted paths in argv instead of executable policy", () => {
    const hostile = '/private/tmp/path\" (allow default) ;\nwith spaces'
    const command = "printf '%s' \"$(printf hello)\"; exit 7"
    const launch = MacSandbox.launch({ ...policy, writableRoots: [hostile] }, "/bin/zsh", ["-c", command], {})
    expect(launch.command).toBe("/usr/bin/sandbox-exec")
    expect(launch.args.slice(-4)).toEqual(["--", "/bin/zsh", "-c", command])
    expect(launch.args).toContain(`-DWRITE_0=${hostile}`)
    expect(launch.args[1]).not.toContain(hostile)
    expect(launch.args[1]).toContain("(deny default process-info*)")
    expect(launch.args[1]).toContain('(import "/System/Library/Sandbox/Profiles/dyld-support.sb")')
    expect(launch.args[1]).not.toContain("(allow network")
    expect(launch.args[1]).toContain('(deny file-write* (subpath (param "PROTECTED_0")))')
    expect(launch.args[1]).toContain(
      '(deny file-read* file-write* file-map-executable (subpath (param "UNREADABLE_0")))',
    )
  })

  test.skipIf(!hasPosixSandboxFixtures())(
    "Seatbelt grants Homebrew runtime paths and protects ancestors of metadata aliases",
    async () => {
      const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-sandbox-policy-")))
      try {
        const host = {
          directory: path.join(root, "workspace"),
          scratch: path.join(root, "scratch"),
          home: path.join(root, "home"),
          config: path.join(root, "config"),
          data: path.join(root, "data"),
          state: path.join(root, "state"),
        }
        await Promise.all(Object.values(host).map((value) => fs.mkdir(value)))
        const target = path.join(host.directory, "nested", "config")
        await fs.mkdir(target, { recursive: true })
        await fs.symlink(target, path.join(host.directory, ".opencode"), "dir")
        const resolved = await MacSandbox.policy(host, {})
        expect(resolved.fullDiskRead).toBe(false)
        const homebrew = ["Cellar", "opt", "bin", "sbin", "lib", "include", "Frameworks"]
          .map((name) => `/opt/homebrew/${name}`)
          .sort()
        expect(resolved.readableRoots).toEqual(homebrew)
        expect(resolved.protectedPaths).toEqual(expect.arrayContaining(homebrew))
        for (const name of ["etc", "var", "share", "Library", "Caskroom"])
          expect(resolved.readableRoots).not.toContain(`/opt/homebrew/${name}`)
        expect(resolved.readableRoots).not.toContain("/opt/homebrew")
        const launch = MacSandbox.launch(resolved, "/bin/sh", ["-c", "true"], {})
        expect(
          launch.args.some(
            (value) => value.startsWith("-DANCESTOR_") && value.endsWith(`=${path.join(host.directory, "nested")}`),
          ),
        ).toBe(true)
      } finally {
        await fs.rm(root, { recursive: true, force: true })
      }
    },
  )
})

// A restricted parent sandbox cannot install another Seatbelt profile. Report the missing
// capability rather than treating a failed sandbox_apply as evidence of command confinement.
const backend = process.platform === "darwin" ? await nativeSandbox() : undefined
const kernel = backend ? test : test.skip

kernel("Seatbelt accepts nonexistent optional readable and protected roots", async () => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-sandbox-missing-")))
  try {
    const missing = path.join(root, "not-installed", "runtime")
    const workspace = path.join(root, "workspace")
    const outside = path.join(root, "outside")
    await fs.mkdir(workspace)
    await fs.writeFile(outside, "must remain unreadable")
    const launch = MacSandbox.launch(
      {
        directory: workspace,
        fullDiskRead: false,
        readableRoots: [missing],
        writableRoots: [workspace],
        protectedPaths: [missing],
        unreadablePaths: [],
        scratch: workspace,
      },
      "/bin/sh",
      ["-c", 'printf ready; ! /bin/cat "$1"', "probe", outside],
      SandboxPolicy.environment(process.env, workspace),
    )
    const result = Bun.spawnSync([launch.command, ...launch.args], { cwd: workspace, env: launch.env })
    expect({ exit: result.exitCode, stderr: result.stderr.toString() }).toMatchObject({ exit: 0 })
    expect(result.stdout.toString()).toBe("ready")
    await expect(fs.stat(missing)).rejects.toMatchObject({ code: "ENOENT" })
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})

kernel("system shells bootstrap and run echo, pwd, and ls inside the sandbox", async () => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-sandbox-startup-")))
  try {
    const workspace = path.join(root, "workspace")
    const scratch = path.join(root, "scratch")
    await Promise.all([workspace, scratch].map((value) => fs.mkdir(value)))
    await fs.writeFile(path.join(workspace, "workspace-marker"), "hello")
    const confined: SandboxPolicy.Policy = {
      directory: workspace,
      fullDiskRead: false,
      readableRoots: [],
      writableRoots: [workspace, scratch],
      scratch,
      protectedPaths: [],
      unreadablePaths: [],
    }
    for (const shell of ["/bin/zsh", "/bin/bash", "/bin/sh"]) {
      const launch = MacSandbox.launch(
        confined,
        shell,
        ["-c", "echo foo && pwd && ls -lah"],
        SandboxPolicy.environment(process.env, scratch),
      )
      const result = Bun.spawnSync([launch.command, ...launch.args], { cwd: workspace, env: launch.env })
      expect({
        shell,
        exit: result.exitCode,
        signal: result.signalCode,
        stderr: result.stderr.toString(),
      }).toMatchObject({ exit: 0 })
      expect(result.stdout.toString()).toStartWith(`foo\n${workspace}\n`)
      expect(result.stdout.toString()).toContain("workspace-marker")
    }
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})

kernel("Seatbelt lets zsh create heredoc files only via the sandbox scratch directory", async () => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-seatbelt-zsh-")))
  try {
    const workspace = path.join(root, "workspace")
    const outside = path.join(root, "outside")
    const scratch = path.join(root, "scratch")
    const host = {
      directory: workspace,
      scratch,
      home: path.join(root, "home"),
      config: path.join(root, "config"),
      data: path.join(root, "data"),
      state: path.join(root, "state"),
    }
    await Promise.all([...Object.values(host), outside].map((value) => fs.mkdir(value)))
    const confined = await MacSandbox.policy(host, {})
    const heredocScript = "cat <<'EOF'\nheredoc works\nEOF"
    const blockedHeredoc = MacSandbox.launch(confined, "/bin/zsh", ["-c", heredocScript], {
      ...process.env,
      TMPPREFIX: path.join(outside, "zsh"),
    })
    expect(
      Bun.spawnSync([blockedHeredoc.command, ...blockedHeredoc.args], { cwd: workspace, env: blockedHeredoc.env })
        .exitCode,
    ).not.toBe(0)
    const heredoc = MacSandbox.launch(
      confined,
      "/bin/zsh",
      ["-c", heredocScript],
      SandboxPolicy.environment({ ...process.env, TMPPREFIX: path.join(outside, "zsh") }, scratch),
    )
    const heredocResult = Bun.spawnSync([heredoc.command, ...heredoc.args], { cwd: workspace, env: heredoc.env })
    expect({
      exit: heredocResult.exitCode,
      stderr: heredocResult.stderr.toString(),
      stdout: heredocResult.stdout.toString(),
    }).toEqual({
      exit: 0,
      stderr: "",
      stdout: "heredoc works\n",
    })
  } finally {
    await fs.rm(root, { recursive: true, force: true })
  }
})

kernel.each([false, true])(
  "Seatbelt protects database aliases and their ancestors with fullDiskRead=%s",
  async (fullDiskRead) => {
    const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-sandbox-db-")))
    try {
      const host = Object.fromEntries(
        ["directory", "scratch", "home", "config", "data", "state"].map((name) => [name, path.join(root, name)]),
      ) as Record<"directory" | "scratch" | "home" | "config" | "data" | "state", string>
      await Promise.all(Object.values(host).map((value) => fs.mkdir(value)))
      const dbDirectory = path.join(host.directory, "db-dir")
      await fs.mkdir(dbDirectory)
      const database = path.join(dbDirectory, "database.db")
      const alias = path.join(host.directory, "database-alias.db")
      await fs.writeFile(database, "private-database")
      await fs.symlink(database, alias)
      const policy = await MacSandbox.policy(host, { fullDiskRead }, [], alias)
      for (const target of [database, alias, `${database}-wal`, `${alias}-shm`, `${database}-journal`]) {
        const launch = MacSandbox.launch(
          policy,
          "/bin/sh",
          ["-c", `cat "$1"; printf changed > "$1"`, "--", target],
          SandboxPolicy.environment(process.env, host.scratch),
        )
        const result = Bun.spawnSync([launch.command, ...launch.args], { cwd: host.directory, env: launch.env })
        expect(result.exitCode).not.toBe(0)
        expect(result.stdout.toString()).toBe("")
      }
      expect(await fs.readFile(database, "utf8")).toBe("private-database")
      const move = MacSandbox.launch(
        policy,
        "/bin/mv",
        [dbDirectory, path.join(host.directory, "moved")],
        SandboxPolicy.environment(process.env, host.scratch),
      )
      expect(Bun.spawnSync([move.command, ...move.args], { cwd: host.directory, env: move.env }).exitCode).not.toBe(0)
      const futureDirectory = path.join(root, "future-db")
      await fs.mkdir(futureDirectory)
      const parentAlias = path.join(host.directory, "db-parent-alias")
      const leafAlias = path.join(host.directory, "db-leaf-alias")
      await fs.symlink(futureDirectory, parentAlias, "dir")
      await fs.symlink(path.join(futureDirectory, "leaf.db"), leafAlias)
      for (const [configured, target] of [
        [path.join(parentAlias, "parent.db"), path.join(futureDirectory, "parent.db")],
        [leafAlias, path.join(futureDirectory, "leaf.db")],
      ]) {
        const futurePolicy = await MacSandbox.policy(host, { fullDiskRead }, [], configured)
        await fs.writeFile(target, "future-private")
        const read = MacSandbox.launch(
          futurePolicy,
          "/bin/cat",
          [target],
          SandboxPolicy.environment(process.env, host.scratch),
        )
        const result = Bun.spawnSync([read.command, ...read.args], { cwd: host.directory, env: read.env })
        expect(result.exitCode).not.toBe(0)
        expect(result.stdout.toString()).toBe("")
      }
    } finally {
      await fs.rm(root, { recursive: true, force: true })
    }
  },
)

const homebrewPython = Bun.which("/opt/homebrew/bin/python3")
const homebrewKernel = backend && homebrewPython ? test : test.skip
homebrewKernel(
  "default strict reads run Homebrew Python and list binaries while excluding configuration and service data",
  async () => {
    if (!homebrewPython) throw new Error("Homebrew Python is unavailable")
    const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "opencode-sandbox-homebrew-")))
    try {
      const host = {
        directory: path.join(root, "workspace"),
        scratch: path.join(root, "scratch"),
        home: path.join(root, "home"),
        config: path.join(root, "config"),
        data: path.join(root, "data"),
        state: path.join(root, "state"),
      }
      await Promise.all(Object.values(host).map((value) => fs.mkdir(value)))
      const confined = await MacSandbox.policy(host, {})
      const run = (command: string, args: string[]) => {
        const launch = MacSandbox.launch(confined, command, args, SandboxPolicy.environment(process.env, host.scratch))
        return Bun.spawnSync([launch.command, ...launch.args], { cwd: host.directory, env: launch.env })
      }
      const python = run(homebrewPython, ["-I", "-B", "-c", 'import ssl, urllib.request; print("runtime ready")'])
      expect({ exit: python.exitCode, signal: python.signalCode, stderr: python.stderr.toString() }).toMatchObject({
        exit: 0,
      })
      expect(python.stdout.toString()).toBe("runtime ready\n")
      expect(run("/bin/ls", ["/opt/homebrew/bin"]).exitCode).toBe(0)
      for (const directory of ["etc", "var", "share", "Library", "Caskroom"])
        expect(run("/bin/ls", [`/opt/homebrew/${directory}`]).exitCode).not.toBe(0)
    } finally {
      await fs.rm(root, { recursive: true, force: true })
    }
  },
)
