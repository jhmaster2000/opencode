import { expect, test } from "bun:test"
import fs from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { AppNodeBuilder } from "@opencode/core/effect/app-node-builder"
import { Location } from "@opencode/core/location"
import { Sandbox } from "@opencode/core/sandbox"
import { AbsolutePath } from "@opencode/core/schema"
import { Workspace } from "@opencode/core/workspace"
import { Effect, Layer } from "effect"
import { SandboxPolicy } from "../src/sandbox/policy"
import { SandboxHostPolicy } from "../src/sandbox/host-policy"
import { location } from "./fixture/location"
import { hasPosixSandboxFixtures, sandboxHost } from "./fixture/sandbox-host"
import { tmpdir } from "./fixture/tmpdir"
import { testEffect } from "./lib/effect"

test("removes harness credentials and startup injections without mutating the session environment", () => {
  const scratch = path.join(os.tmpdir(), "sandbox-scratch")
  const inherited = {
    PATH: "/usr/bin:/bin",
    HOME: "/Users/example",
    TERM: "xterm",
    OPENCODE_PASSWORD: "secret",
    OPENCODE_SERVER_PASSWORD: "secret",
    OPENCODE_CONFIG_CONTENT: "config",
    OPENAI_API_KEY: "secret",
    AWS_ACCESS_KEY_ID: "secret",
    AWS_SECRET_ACCESS_KEY: "secret",
    GH_TOKEN: "secret",
    NPM_TOKEN: "secret",
    CODEX_API_KEY: "secret",
    SSH_AUTH_SOCK: "/tmp/agent.sock",
    BASH_ENV: "/tmp/injected",
    ENV: "/tmp/injected",
    NODE_OPTIONS: "--require=/tmp/injected",
    DYLD_INSERT_LIBRARIES: "/tmp/injected",
    TMPDIR: "/shared",
    TMPPREFIX: "/shared/zsh",
  }
  const env = SandboxPolicy.environment(inherited, scratch)
  expect(env).toEqual({
    PATH: inherited.PATH,
    HOME: inherited.HOME,
    TERM: "xterm",
    TMPDIR: scratch,
    TMP: scratch,
    TEMP: scratch,
    TMPPREFIX: path.join(scratch, "zsh"),
  })
  expect(inherited.OPENCODE_PASSWORD).toBe("secret")
  expect(inherited.TMPDIR).toBe("/shared")
  expect(inherited.TMPPREFIX).toBe("/shared/zsh")
})

// This fixture uses a quoted POSIX filename and an unprivileged symlink.
test.skipIf(!hasPosixSandboxFixtures())(
  "canonicalizes symlinked grants and rejects relative or missing roots",
  async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "opencode-sandbox-paths-"))
    try {
      const actual = path.join(root, 'directory with "quotes"')
      await fs.mkdir(actual)
      const alias = path.join(root, "alias")
      await fs.symlink(actual, alias, "dir")
      expect(await SandboxHostPolicy.roots([alias, actual])).toEqual([await fs.realpath(actual)])
      await expect(SandboxHostPolicy.roots(["relative"])).rejects.toThrow("must be absolute")
      await expect(SandboxHostPolicy.roots([path.join(root, "missing")])).rejects.toThrow()
    } finally {
      await fs.rm(root, { recursive: true, force: true })
    }
  },
)

const remote = testEffect(
  AppNodeBuilder.build(Sandbox.node, [
    Sandbox.settingsNode.replace(Layer.succeed(Sandbox.Settings, { enabled: true })),
    Location.node.replace(
      Layer.succeed(
        Location.Service,
        location({ directory: AbsolutePath.make("/remote"), workspaceID: Workspace.ID.make("wrk_sandbox_test") }),
      ),
    ),
  ]),
)

remote.effect("remote locations initialize but cannot prepare a sandboxed shell launch", () =>
  Effect.gen(function* () {
    const sandbox = yield* Sandbox.Service
    expect(sandbox.enabled).toBe(true)
    expect(yield* sandbox.status()).toMatchObject({ active: false, escalation: "disabled" })
    const error = yield* Effect.flip(
      sandbox.prepare({ command: "pwd", cwd: "/remote", shell: "/bin/sh", timeout: 0, env: {} }, false),
    )
    expect(error.message).toContain("Shell sandboxing requires a supported local execution host")
  }),
)

test.skipIf(!hasPosixSandboxFixtures())("protects policy aliases and rejects grants over host state", async () => {
  await using temporary = await tmpdir()
  const root = temporary.path
  const host = await sandboxHost(root)
  const target = path.join(host.directory, "nested", "config")
  await fs.mkdir(target, { recursive: true })
  await fs.symlink(target, path.join(host.directory, ".opencode"), "dir")
  const resolved = await SandboxHostPolicy.policy(host, {}, [])
  expect(await SandboxHostPolicy.policy(host, { fullDiskRead: true }, [])).toEqual({ ...resolved, fullDiskRead: true })
  expect(resolved.writableRoots).toEqual([host.scratch, host.directory].sort())
  expect(resolved.protectedPaths).toContain(path.join(host.directory, "opencode.json"))
  expect(resolved.protectedPaths).toContain(target)
  expect(resolved.unreadablePaths).toContain(host.data)
  const grant = path.join(host.directory, "grant")
  await fs.mkdir(grant)
  const pinned = await SandboxHostPolicy.policy(host, { readableRoots: [grant] }, [])
  expect(pinned.readableRoots).toEqual([grant])
  expect(pinned.protectedPaths).toContain(grant)
  expect(
    (await SandboxHostPolicy.policy(host, { fullDiskRead: true, readableRoots: [grant] }, [])).protectedPaths,
  ).toContain(grant)
  await fs.rmdir(grant)
  await fs.symlink(host.home, grant, "dir")
  await expect(SandboxHostPolicy.policy(host, { readableRoots: [grant] }, [])).rejects.toThrow(
    "Configured sandbox root changed",
  )
  await expect(SandboxHostPolicy.policy(host, { writableRoots: [root] }, [])).rejects.toThrow("must not contain")
  await expect(SandboxHostPolicy.policy({ ...host, directory: host.home }, {}, [])).rejects.toThrow("home directory")
  await expect(SandboxHostPolicy.policy({ ...host, directory: path.parse(root).root }, {}, [])).rejects.toThrow(
    "filesystem root",
  )
})
