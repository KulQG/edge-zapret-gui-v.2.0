# Windows release checklist

This is a gate for the **specific installer being published**. Record its version, hashes, test system, and results. Empty boxes are unverified.

## Source and build

- [ ] Review the final diff, Tauri capabilities, NSIS hooks, bundled licenses, and absence of developer data and secrets.
- [ ] Confirm `src/assets/default/alt.png` SHA-256 is `51A2A88B87D08690FD907839F9E02D8648C6179659FAEB3B4343D0929A189F19`; check the wordmark and saved appearance.
- [ ] From a clean checkout run `npm ci`, `npm run build`, `cargo fmt --check`, `cargo check --offline --locked`, and `cargo test --offline --locked --lib` with Rust 1.90.0.
- [ ] Run `npm run package:windows`, `npm run verify:release`, and `git diff --check`; save logs and the final NSIS SHA-256.
- [ ] Confirm the installed GUI and helper are Windows GUI-subsystem binaries and the app is installed in protected Program Files.

## Engine behavior

- [ ] Confirm strategy IDs resolve only to official `general*.bat` inside the verified managed release; the helper uses fixed system `cmd.exe`, normal UAC, and no simulated console input.
- [ ] With VPN **off**, start `general (FAKE TLS AUTO ALT2).bat` from the GUI; play and seek YouTube video before and after hiding the owned console. Record any startup flash.
- [ ] Confirm Start/Stop targets only the app-owned process using PID, creation time, canonical path, and launch relationship. Closing and reopening the GUI must retain and rediscover a running strategy.
- [ ] Open official `service.bat` from the GUI and confirm its console remains visible. Verify service changes there, including removal before GUI uninstall.
- [ ] Confirm external `winws.exe`, zapret service, terminal windows, and WinDivert consumers are not stopped or hidden.

## Update and rollback

- [ ] First install from the official release asset, including a release without runtime-created `*-user.txt` files. Confirm the new engine remains stopped.
- [ ] Update from stopped and running BAT modes; confirm prior mode and strategy are restored. An installed service must block update before download until its restore path is implemented.
- [ ] After playback/seek testing without VPN, use the retained previous-release rollback and check the former mode/strategy and user files.
- [ ] Exercise download interruption, incorrect digest, invalid/oversized ZIP, missing required archive files, locked engine files, launch failure, interrupted journal recovery, and cleanup failure. A committed update must never roll back from a partially deleted backup.
- [ ] Confirm user lists, GameFilter settings, selected fake payloads, appearance, config, history, and logs survive both success and failure.

## Installer and publication

- [ ] Follow the [Windows test plan](windows-test-plan.md) on Windows 10 and 11 x64, including ordinary and administrator accounts, UAC cancellation, WebView2, upgrade, and uninstall.
- [ ] Confirm GUI uninstall preserves ProgramData engine and LocalAppData user data. An installed zapret service must block uninstall with instructions for the visible official service console.
- [ ] Resolve all failed or blocked acceptance scenarios; retest the final rebuilt installer.
- [ ] Sign the final installer with Authenticode and verify publisher, certificate chain, and timestamp, or clearly label the build **unsigned**. Record the hash of the exact final file.
- [ ] Do not advertise automatic **GUI** updates; no updater endpoint or signing key is configured. Document any remaining unverified Windows behavior in release notes.

Running `winws.exe`, WinDivert, or an HTTP probe does not prove playback works without VPN. Do not mark the network acceptance boxes from process or connectivity checks alone.
