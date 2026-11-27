export * as Sandbox from "./sandbox.js"

import fs from "node:fs/promises"
import path from "node:path"
import { Cache, Context, Effect, Layer, Schema } from "effect"
import { makeGlobalNode, makeLocationNode } from "@opencode/util/effect/app-node"
import { Global } from "@opencode/util/global"
import { AppProcess } from "@opencode/util/process"
import type { ShellCreateBefore } from "@opencode/plugin/effect/shell"
import { Location } from "./location.js"
import { Reference } from "./reference.js"
import { SandboxBackend } from "./sandbox/backend.js"
import { SandboxHostPolicy } from "./sandbox/host-policy.js"
import { SandboxPolicy } from "./sandbox/policy.js"
import { SandboxGitConfig } from "./sandbox/git-config.js"
import { ShellSelect } from "./shell/select.js"
import type { SandboxFiles } from "./sandbox/files.js"

export type Options = SandboxPolicy.Options
export type Launch = SandboxPolicy.Launch

export const Options = Schema.Struct({
  enabled: Schema.optional(Schema.Boolean),
  approval: Schema.optional(Schema.Literals(["on-request", "never"])),
  fullDiskRead: Schema.optional(Schema.Boolean),
  allowGitWrites: Schema.optional(Schema.Boolean),
  linux: Schema.optional(Schema.Struct({ binary: Schema.optional(Schema.String) })),
  readableRoots: Schema.optional(Schema.Array(Schema.String)),
  writableRoots: Schema.optional(Schema.Array(Schema.String)),
})

export class UnavailableError extends Schema.TaggedError<UnavailableError>()("Sandbox.UnavailableError", {
  message: Schema.String,
}) {}

export interface Interface {
  readonly enabled: boolean
  readonly unavailable?: UnavailableError
  readonly scratch?: string
  readonly approval: "on-request" | "never"
  readonly fullDiskRead: boolean
  readonly status: () => Effect.Effect<
    {
      readonly active: boolean
      readonly reads: "unrestricted" | "restricted" | "broad"
      readonly escalation: "on-request" | "never" | "disabled"
      readonly writableRoots: readonly string[]
      readonly readableRoots: readonly string[]
    },
    UnavailableError
  >
  readonly checkLocation: (target: Location.Ref) => Effect.Effect<void, UnavailableError>
  readonly files: Effect.Effect<SandboxFiles.Interface, UnavailableError>
  readonly search: (command: string, cwd?: string) => Effect.Effect<Launch, UnavailableError>
  readonly command: (input: Launch, cwd?: string) => Effect.Effect<Launch, UnavailableError>
  readonly prepare: (invocation: ShellCreateBefore, escalated: boolean) => Effect.Effect<Launch, UnavailableError>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/Sandbox") {}

export class Settings extends Context.Service<
  Settings,
  Options & { readonly databasePath?: string; readonly backend?: SandboxBackend.Interface }
>()("@opencode/Sandbox/Settings") {}

// The server builds this global node before reporting readiness; Location eviction
// must neither re-resolve configured aliases nor repeat the host runtime probe.
export const settingsConfigured = (input: Options = {}, databasePath?: string) =>
  makeGlobalNode({
    service: Settings,
    layer: Layer.effect(
      Settings,
      Effect.gen(function* () {
        if (input.enabled !== true) return Settings.of({ ...input })
        const global = yield* Global.Service
        const backend = yield* Effect.tryPromise({
          try: () => SandboxBackend.select(process.platform, input),
          catch: (cause) => new UnavailableError({ message: `Unable to initialize sandbox backend: ${cause}` }),
        }).pipe(Effect.orDie)
        const options = yield* Effect.tryPromise({
          try: async () => ({
            ...input,
            backend,
            readableRoots: await SandboxHostPolicy.roots(input.readableRoots ?? []),
            writableRoots: await SandboxHostPolicy.roots(input.writableRoots ?? []),
            databasePath:
              databasePath && databasePath !== ":memory:" ? path.resolve(global.data, databasePath) : undefined,
          }),
          catch: (cause) =>
            new UnavailableError({
              message: `Invalid sandbox roots: ${cause}. Configured roots must be existing absolute paths.`,
            }),
        }).pipe(Effect.orDie)
        yield* Effect.scoped(
          Effect.gen(function* () {
            const scratch = yield* Effect.acquireRelease(
              Effect.tryPromise(() => fs.mkdtemp(path.join(global.tmp, "sandbox-check-"))),
              (directory) => Effect.promise(() => fs.rm(directory, { recursive: true, force: true })),
            )
            const directory = path.join(scratch, "workspace")
            yield* Effect.tryPromise(() => Promise.all([fs.mkdir(directory), fs.mkdir(path.join(scratch, ".runtime"))]))
            const policy = yield* Effect.tryPromise(() =>
              backend.policy({ ...global, directory, scratch }, options, [], options.databasePath),
            )
            const { SandboxCheck } = yield* Effect.promise(() => import("./sandbox/check.js"))
            yield* SandboxCheck.run(backend, policy)
          }),
        ).pipe(
          Effect.mapError(
            (cause) =>
              new UnavailableError({
                message: `Sandbox startup check failed: ${cause instanceof Error ? cause.message : cause}. Check the ${backend.name} prerequisites and runtime access. No unsandboxed fallback was used.`,
              }),
          ),
          Effect.orDie,
        )
        return Settings.of(options)
      }),
    ),
    deps: [Global.node, AppProcess.node],
  })

export const settingsNode = settingsConfigured()

export const configured = (input?: Options) => {
  return makeLocationNode({
    service: Service,
    layer: Layer.effect(
      Service,
      Effect.gen(function* () {
        const location = yield* Location.Service
        const global = yield* Global.Service
        const subprocess = yield* AppProcess.Service
        const references = yield* Reference.Service
        const options = yield* Settings
        const enabled = options.enabled === true
        const approval = options.approval ?? "on-request"
        const unavailable =
          enabled && location.workspaceID !== undefined
            ? new UnavailableError({ message: "Sandboxed operations require a supported local execution host." })
            : undefined
        // Scratch lives as long as this Location, including its background jobs.
        const scratch =
          enabled && options.backend && location.workspaceID === undefined
            ? yield* Effect.acquireRelease(
                Effect.tryPromise({
                  try: () => fs.mkdtemp(path.join(global.tmp, "sandbox-")),
                  catch: (cause) =>
                    new UnavailableError({ message: `Cannot create sandbox scratch directory: ${cause}` }),
                }).pipe(Effect.orDie),
                (directory) => Effect.promise(() => fs.rm(directory, { recursive: true, force: true })),
              )
            : undefined
        if (scratch) yield* Effect.tryPromise(() => fs.mkdir(path.join(scratch, ".runtime"))).pipe(Effect.orDie)
        const backend = scratch ? options.backend : undefined
        const gitConfigFiles = scratch
          ? yield* SandboxGitConfig.discover(location.directory, SandboxPolicy.environment(process.env, scratch))
          : []
        // Resolve grants once. Re-resolving a workspace-controlled symlink on every invocation
        // would let a command redirect a configured grant to a different host directory.
        const policy =
          backend && scratch
            ? yield* Effect.tryPromise({
                try: () =>
                  backend.policy(
                    { ...global, directory: location.directory, scratch },
                    options,
                    gitConfigFiles,
                    options.databasePath,
                  ),
                catch: (cause) => new UnavailableError({ message: `Unable to initialize shell sandbox: ${cause}` }),
              }).pipe(Effect.orDie)
            : undefined

        if (enabled && !unavailable && (!backend || !policy || !scratch))
          return yield* Effect.die(
            new UnavailableError({ message: "Sandboxed Locations require a supported local execution host." }),
          )
        if (policy && backend) {
          const { SandboxCheck } = yield* Effect.promise(() => import("./sandbox/check.js"))
          yield* SandboxCheck.run(backend, policy, false).pipe(
            Effect.mapError(
              (cause) =>
                new UnavailableError({
                  message: `Sandbox workspace check failed: ${cause instanceof Error ? cause.message : cause}`,
                }),
            ),
            Effect.orDie,
          )
        }

        // Reference registrations can change after Location startup, including asynchronous Git clones.
        // Pin each existing alias for this Location so a workspace symlink cannot redirect its grant.
        const pinnedReferences = new Map<string, { root: string; missing: boolean }>()
        const effectivePolicy = Effect.fn("Sandbox.effectivePolicy")(function* () {
          if (!policy || !backend) return yield* new UnavailableError({ message: "Sandbox policy is unavailable." })
          const entries = yield* references.list()
          return yield* Effect.tryPromise({
            try: async () => {
              const roots = await Promise.all(
                entries.map(async (entry) => {
                  const pinned = pinnedReferences.get(entry.path)
                  const resolved = await fs.realpath(entry.path).catch((error: NodeJS.ErrnoException) => {
                    if (error.code === "ENOENT" || error.code === "ENOTDIR") return undefined
                    throw error
                  })
                  // A missing grant can become a directory in place, but a new
                  // symlink must never redirect it to a different host path.
                  if (pinned?.missing) {
                    if (!resolved) return pinned.root
                    if (resolved !== pinned.root || !(await fs.stat(resolved)).isDirectory()) return undefined
                    return pinned.root
                  }
                  if (!resolved) {
                    let parent = path.dirname(entry.path)
                    while (true) {
                      const canonical = await fs.realpath(parent).catch((error: NodeJS.ErrnoException) => {
                        if (error.code === "ENOENT" || error.code === "ENOTDIR") return undefined
                        throw error
                      })
                      if (canonical) {
                        const root = path.join(canonical, path.relative(parent, entry.path))
                        pinnedReferences.set(entry.path, { root, missing: true })
                        return root
                      }
                      const next = path.dirname(parent)
                      if (next === parent) throw new Error(`Cannot resolve reference parent: ${entry.path}`)
                      parent = next
                    }
                  }
                  if (!(await fs.stat(resolved)).isDirectory()) return undefined
                  if (pinned !== undefined && pinned.root !== resolved)
                    throw new Error(`Reference target changed: ${entry.path}`)
                  pinnedReferences.set(entry.path, { root: resolved, missing: false })
                  return resolved
                }),
              )
              const grants = await SandboxHostPolicy.references(
                policy,
                global,
                roots.filter((root): root is string => root !== undefined),
              )
              const aliases = entries.flatMap((entry, index) => {
                const target = roots[index]
                return target && target !== entry.path && pinnedReferences.get(entry.path)?.missing === false
                  ? [{ path: entry.path, target }]
                  : []
              })
              return { ...grants, referenceAliases: aliases }
            },
            catch: (cause) => new UnavailableError({ message: `Unable to prepare reference access: ${cause}` }),
          })
        })

        const searches = yield* Cache.make({
          capacity: 1,
          lookup: (command: string) =>
            Effect.tryPromise({
              try: async () => {
                if (!enabled || !backend || !policy || !scratch)
                  throw new Error("Confined search requires a supported local execution host")
                await fs.access(backend.executable, fs.constants.X_OK)
                // The managed binary can live under host state, which is intentionally unreadable.
                // Copy this one trusted executable into private scratch; never grant the state directory.
                const directory = await fs.mkdtemp(path.join(scratch, ".runtime", "search-"))
                const binary = path.join(directory, "rg")
                await fs.copyFile(await fs.realpath(command), binary)
                await fs.chmod(binary, 0o500)
                return { binary, directory }
              },
              catch: (cause) => new UnavailableError({ message: `Unable to prepare confined search: ${cause}` }),
            }),
        })

        const command = Effect.fn("Sandbox.command")(function* (input: Launch, cwd?: string) {
          if (!enabled || !backend || !policy || !scratch)
            return yield* new UnavailableError({
              message: "Command sandboxing requires a supported local execution host.",
            })
          const current = yield* effectivePolicy()
          return yield* Effect.tryPromise({
            try: async () => {
              await fs.access(backend.executable, fs.constants.X_OK)
              return backend.launch(
                current,
                input.command,
                input.args,
                SandboxPolicy.environment(input.env, scratch),
                cwd,
              )
            },
            catch: (cause) => new UnavailableError({ message: `Unable to prepare command sandbox: ${cause}` }),
          })
        })

        return Service.of({
          enabled,
          unavailable,
          scratch,
          approval,
          fullDiskRead: options.fullDiskRead ?? false,
          status: Effect.fn("Sandbox.status")(function* () {
            const current = policy ? yield* effectivePolicy() : undefined
            return {
              active: enabled && current !== undefined,
              reads: enabled ? (options.fullDiskRead ? "broad" : "restricted") : "unrestricted",
              escalation: current ? approval : "disabled",
              writableRoots: current?.writableRoots ?? [],
              readableRoots:
                current && backend ? [...backend.readableRoots(current), ...(current.gitConfigFiles ?? [])] : [],
            }
          }),
          search: Effect.fn("Sandbox.search")(function* (command, cwd) {
            if (!backend || !scratch) return yield* new UnavailableError({ message: "Sandbox search is unavailable." })
            const current = yield* effectivePolicy()
            const { binary, directory } = yield* Cache.get(searches, command)
            return yield* Effect.tryPromise({
              try: async () =>
                backend.launch(
                  { ...current, protectedPaths: [...current.protectedPaths, directory] },
                  binary,
                  [],
                  { PATH: backend.trustedPath, HOME: scratch, TMPDIR: scratch },
                  cwd,
                ),
              catch: (cause) => new UnavailableError({ message: `Unable to prepare sandbox search: ${cause}` }),
            })
          }),
          command,
          checkLocation: Effect.fn("Sandbox.checkLocation")(function* (target: Location.Ref) {
            if (!enabled) return
            if (!policy || target.workspaceID !== location.workspaceID)
              return yield* new UnavailableError({
                message: "Subagents require the caller's local sandbox execution host.",
              })
            const directory = yield* Effect.tryPromise({
              try: () => fs.realpath(target.directory),
              catch: (cause) => new UnavailableError({ message: `Cannot verify subagent sandbox location: ${cause}` }),
            })
            if (directory !== policy.directory)
              return yield* new UnavailableError({
                message:
                  "Subagents must use the caller's sandbox workspace. Start a new child here, or explicitly move the existing child back before continuing it.",
              })
          }),
          files: Effect.gen(function* () {
            if (!enabled || !backend || !policy || !scratch)
              return yield* new UnavailableError({
                message: "Confined file operations require sandboxing on a supported local execution host.",
              })
            const { SandboxFiles } = yield* Effect.promise(() => import("./sandbox/files.js"))
            const { SandboxFileWorker } = yield* Effect.promise(() => import("./sandbox/file-worker.js"))
            const launch = () =>
              Effect.gen(function* () {
                const current = yield* effectivePolicy()
                return yield* Effect.tryPromise({
                  try: async () => {
                    await fs.access(backend.executable, fs.constants.X_OK)
                    return backend.fileLaunch(
                      current,
                      await fs.realpath(process.execPath),
                      SandboxFileWorker.configured(current),
                    )
                  },
                  catch: (cause) =>
                    new UnavailableError({ message: `Unable to prepare confined file operations: ${cause}` }),
                })
              })
            return SandboxFiles.make({ process: subprocess, launch, directory: location.directory, cwd: scratch })
          }),
          prepare: Effect.fn("Sandbox.prepare")(function* (invocation: ShellCreateBefore, escalated: boolean) {
            if (!enabled)
              return yield* new UnavailableError({ message: "Shell sandboxing is not enabled on this server." })
            if (!backend || !policy || !scratch)
              return yield* new UnavailableError({
                message: "Shell sandboxing requires a supported local execution host.",
              })
            if (escalated && approval === "never")
              return yield* new UnavailableError({ message: "Sandbox escalation is disabled by the server." })
            const current = escalated ? policy : yield* effectivePolicy()
            return yield* Effect.tryPromise({
              try: async () => {
                const command = invocation.shell
                const args = ShellSelect.args(command, invocation.command)
                const env = SandboxPolicy.environment(invocation.env, scratch)
                if (escalated) return { command, args, env }
                await fs.access(backend.executable, fs.constants.X_OK)
                return backend.launch(current, command, args, env, invocation.cwd)
              },
              catch: (cause) => new UnavailableError({ message: `Unable to prepare shell sandbox: ${cause}` }),
            })
          }),
        })
      }),
    ),
    deps: [
      input === undefined ? settingsNode : settingsConfigured(input),
      Location.node,
      Global.node,
      AppProcess.node,
      Reference.node,
    ],
  })
}

export const node = configured()
