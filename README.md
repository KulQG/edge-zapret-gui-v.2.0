# ZAPRET GUI

Windows desktop controller for the official Flowseal zapret release, built with Tauri v2, Rust, and vanilla TypeScript/HTML/CSS. The interface is in Russian.

## Use

The Home screen has a strategy selector, **Start/Stop**, **Update**, rollback when a previous engine is available, and a button that opens the official `service.bat` in a **visible** console. The bundled lineup image is the default background; Appearance customizes the background while preserving existing local settings and assets. The ZAPRET wordmark remains on Home. Native service management and guided diagnostics are no longer in the GUI.

Start runs the selected official `general*.bat` from the verified managed release through the system `cmd.exe` with normal Windows UAC. The helper hides the console owned by that launch without closing it. Stop targets only the verified process owned by the app. Closing the GUI leaves a running strategy active; reopen the GUI to see its status and stop it. The console may briefly flash at startup; zero-flash launch has not been proven. Use the visible official service menu for service tasks. Its console is intentionally left open for interaction.

The known working strategy is `general (FAKE TLS AUTO ALT2).bat`. In a separate manual test, the user confirmed YouTube playback without VPN with its official BAT console visible and again after that same console was hidden. GUI Start/Stop, process persistence across GUI exit, and hidden-console ownership have been checked mechanically. **Playback and seeking without VPN after starting from the GUI have not yet been verified by the user.** A running `winws.exe` or WinDivert alone does not establish that traffic bypass works.

## ALT tests

The **Тесты ALT** page checks the currently running app-owned strategy without restarting it, or scans all or selected official ALT BATs. Choose YouTube, Discord, or both; Google and Cloudflare are always shown as reference checks. Each fixed HTTPS endpoint is checked with HTTP/1.1, TLS 1.2, and TLS 1.3. Addresses are checked concurrently for each ALT. A green result means curl received an HTTP response of any status; it does not prove playback or Discord functionality. Each ALT appears in a compact row with per-service indicators and average response times. Expand a row for HTTP codes, timings, and errors. Fast mode moves to the next ALT after the first failed required check. The scan can be cancelled.

A scan uses one normal UAC request, stops a previously running app-owned strategy, tests candidates sequentially, then restores the original strategy or stopped state. It never runs the upstream test script, which can stop unrelated `winws.exe` processes. If a scan is interrupted, a protected journal blocks new operations until recovery is attempted from the Tests page. Ambiguous process identity blocks automatic stopping. **Full scan, cancellation, and recovery acceptance in the installed app remain open.** Test without VPN to assess the bypass.

## Engine update and rollback

Update downloads an official release ZIP, checks its source, published digest when available, size and archive paths, and stages/validates it before stopping the current mode. Validation uses files shipped in the archive; the official BAT creates runtime `*-user.txt` files when needed. A first installation leaves the engine stopped. An update snapshots the prior mode and strategy, swaps the staged release, and restarts a previously running app-owned BAT strategy. A previously stopped mode stays stopped. The previous release is retained for the user rollback control. Failed replacement or restart attempts to restore the former release and mode. An installed zapret service blocks update before download because safe service restoration is not implemented.

User lists, GameFilter settings, selected fake payloads, appearance, configuration, logs, and history are preserved. The active engine is under `%ProgramData%\ZapretGui\engine\current`; user data is under `%LOCALAPPDATA%\ZapretGui`. The engine rollback control changes the **engine**, not the installed GUI. A failed cleanup after a committed update is reported without undoing a partly cleaned release.

Old guided-test history and recovery files remain on disk, but the guided-test UI/API has been removed. The new GUI does not automatically recover a historical guided-test marker. If one exists, inspect the running mode before starting another strategy; no migration deletes that marker.

The update and rollback paths have automated tests, but **no live engine update or rollback has been performed with this redesign**. Check playback and seeking without VPN before and after an update on a test system. Do not infer connectivity from a process or HTTP status alone.

## Development and packaging

Requirements: Windows x64, Node.js, Rust 1.90.0 (`rust-toolchain.toml`), Visual Studio C++ Build Tools/Windows SDK, and [Tauri's Windows prerequisites](https://v2.tauri.app/start/prerequisites/#windows).

```powershell
npm ci
npm run build
cd src-tauri
cargo fmt --check
cargo check --offline --locked
cargo test --offline --locked --lib
```

To build and audit the NSIS installer from the repository root:

```powershell
npm run package:windows
npm run verify:release
```

The installer is emitted under `src-tauri/target/release/bundle/nsis`. It installs to protected Program Files and prepares protected engine storage in ProgramData. It does not remove engine or user data on uninstall. Uninstall is blocked while a zapret service is installed; remove that service through the visible official `service.bat` console first. The installer is **unsigned**. Build and release audits do not replace [Windows acceptance testing](docs/windows-test-plan.md) or the [release checklist](docs/release-checklist.md).

The GUI has no automatic application updater or update endpoint. The Update button updates Flowseal only.

The bundled `src/assets/default/alt.png` is unchanged (SHA-256 `51A2A88B87D08690FD907839F9E02D8648C6179659FAEB3B4343D0929A189F19`). Keep its license and attribution files with the project.
