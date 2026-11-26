export * as SandboxBackend from "./backend.js"

import type { SandboxHostPolicy } from "./host-policy.js"
import type { SandboxPolicy } from "./policy.js"

export type Launcher = (
  policy: SandboxPolicy.Policy,
  command: string,
  args: readonly string[],
  env: SandboxPolicy.Launch["env"],
  cwd?: string,
) => SandboxPolicy.Launch | Promise<SandboxPolicy.Launch>

export interface Interface {
  readonly name: string
  readonly executable: string
  readonly trustedPath: string
  readonly probe: (policy: SandboxPolicy.Policy) => SandboxPolicy.Launch | Promise<SandboxPolicy.Launch>
  readonly policy: (
    host: SandboxHostPolicy.Host,
    options: SandboxPolicy.Options,
    gitConfigFiles?: readonly string[],
    databasePath?: string,
  ) => Promise<SandboxPolicy.Policy>
  readonly readableRoots: (policy: SandboxPolicy.Policy) => readonly string[]
  readonly launch: Launcher
  readonly fileLaunch: (
    policy: SandboxPolicy.Policy,
    runtime: string,
    program: string,
  ) => SandboxPolicy.Launch | Promise<SandboxPolicy.Launch>
}

export async function select(platform: NodeJS.Platform, options: SandboxPolicy.Options): Promise<Interface> {
  switch (platform) {
    case "darwin":
      return (await import("./macos.js")).MacSandbox.backend()
    case "linux":
      // Linux uses these options to select and vet Bubblewrap before probing it.
      // All working backends receive the shared options later through backend.policy(...)
      return (await import("./linux.js")).LinuxSandbox.backend(options.linux?.binary, options.writableRoots)
    case "win32":
      return (await import("./windows.js")).WindowsSandbox.backend()
    default:
      throw new Error(`Sandboxing is unavailable on ${platform}`)
  }
}

export function posixProbe(launch: Launcher, trustedPath: string): Interface["probe"] {
  return (policy) =>
    launch(
      policy,
      "/bin/sh",
      ["-c", "exit 0"],
      { PATH: trustedPath, HOME: policy.scratch, TMPDIR: policy.scratch },
      policy.directory,
    )
}

/** The POSIX file worker inherits the policy, plus a read-only grant to its runtime. */
export function posixFileLauncher<A extends ReturnType<Launcher>>(
  launch: (...args: Parameters<Launcher>) => A,
  trustedPath: string,
) {
  return (policy: SandboxPolicy.Policy, runtime: string, program: string): A =>
    launch(
      {
        ...policy,
        readableRoots: [...policy.readableRoots, runtime],
        protectedPaths: [...policy.protectedPaths, runtime],
      },
      runtime,
      process.versions.bun
        ? ["--config=/dev/null", "--no-env-file", "--no-addons", "--no-macros", "--eval", program]
        : ["--input-type=commonjs", "--eval", program],
      {
        PATH: trustedPath,
        HOME: policy.scratch,
        TMPDIR: policy.scratch,
        TMP: policy.scratch,
        TEMP: policy.scratch,
        BUN_BE_BUN: "1",
        BUN_RUNTIME_TRANSPILER_CACHE_PATH: "0",
        DO_NOT_TRACK: "1",
      },
      policy.scratch,
    )
}
