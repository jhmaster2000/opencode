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
  readonly trustedPath?: string
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

/** The file worker inherits the policy, plus a read-only grant to its runtime. */
export function fileLauncher<A extends ReturnType<Launcher>>(
  launch: (...args: Parameters<Launcher>) => A,
  trustedPath = "/usr/bin:/bin",
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
