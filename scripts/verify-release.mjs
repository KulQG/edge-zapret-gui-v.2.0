import { readFile, readdir, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const root = fileURLToPath(new URL('../', import.meta.url))
const read = (name) => readFile(path.join(root, name))
const json = async (name) => JSON.parse(await read(name))
const config = await json('src-tauri/tauri.conf.json')
const pkg = await json('package.json')
const cargo = (await read('src-tauri/Cargo.toml')).toString()
assert.equal(config.version, pkg.version)
assert.equal(cargo.match(/^version = "([^"]+)"/m)?.[1], pkg.version)
assert.deepEqual(config.bundle.targets, ['nsis'])
assert.equal(config.bundle.windows.nsis.installMode, 'perMachine')
assert.deepEqual(config.bundle.windows.nsis.languages, ['Russian'])
assert.equal(config.bundle.windows.nsis.installerHooks, './windows/hooks.nsh')
assert.equal(config.bundle.windows.webviewInstallMode.type, 'downloadBootstrapper')
assert.equal(config.bundle.windows.allowDowngrades, false)
assert.equal(config.bundle.createUpdaterArtifacts, undefined)
assert.equal(config.plugins?.updater, undefined)
assert.equal(config.app.security.csp, "default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self'; connect-src ipc: http://ipc.localhost")

const capabilities = await readdir(path.join(root, 'src-tauri/capabilities'))
assert.deepEqual(capabilities, ['main.json'])
const capability = await json('src-tauri/capabilities/main.json')
assert.deepEqual(capability.windows, ['main'])
assert.equal(capability.remote, undefined)
const lib = (await read('src-tauri/src/lib.rs')).toString()
const registered = lib.match(/generate_handler!\[([\s\S]*?)\]/)?.[1]
assert.ok(registered)
const expected = registered.split(',').map((name) => name.trim()).filter(Boolean)
  .map((name) => `allow-${name.replaceAll('_', '-')}`)
assert.deepEqual([...capability.permissions].sort(), [...expected, 'core:event:allow-listen'].sort())

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex')
assert.equal(hash(await read('src/assets/default/alt.png')), '51a2a88b87d08690fd907839f9e02d8648c6179659faeb3b4343d0929a189f19')
const executable = await read('src-tauri/target/release/zapret-gui.exe')
assert.equal(executable.readUInt16LE(0), 0x5a4d)
const pe = executable.readUInt32LE(0x3c)
assert.equal(executable.readUInt32LE(pe), 0x4550)
assert.equal(executable.readUInt16LE(pe + 4), 0x8664, 'Expected Windows x64')
assert.equal(executable.readUInt16LE(pe + 24 + 68), 2, 'Expected GUI subsystem, including elevated helper')
const bundle = path.join(root, 'src-tauri/target/release/bundle/nsis')
const installer = `ZAPRET GUI_${pkg.version}_x64-setup.exe`
const installerBytes = await readFile(path.join(bundle, installer))
assert.ok(installerBytes.length > 100_000)
const sums = `${hash(installerBytes)}  ${installer}\n${hash(executable)}  ../../zapret-gui.exe\n`
await writeFile(path.join(bundle, 'SHA256SUMS.txt'), sums)
console.log('PASS: versions, Russian per-machine NSIS, capabilities, CSP, default mascot, x64 GUI executable, installer')
console.log(sums.trim())
