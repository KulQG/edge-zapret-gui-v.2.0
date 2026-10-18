# ZAPRET GUI contributor notes

## Current application

- Windows x64 desktop app: Tauri v2, Rust, vanilla TypeScript, HTML, and CSS. The UI is Russian.
- `src/main.ts` renders Home, ALT Tests, and Appearance; `src/style.css` styles them. `src/bridge.ts` defines typed Tauri IPC calls.
- Home runs an official managed `general*.bat` strategy, stops only the app-owned process, updates the Flowseal engine, offers rollback, and opens the official `service.bat` in a visible console.
- Appearance customizes a full-window background. Preserve `src/assets/default/alt-lineup.png`, the ZAPRET wordmark, saved appearance data, and `src/assets/default/alt.png` byte-for-byte. The latter is retained for compatibility, not displayed. Its SHA-256 is `51A2A88B87D08690FD907839F9E02D8648C6179659FAEB3B4343D0929A189F19`.
- ALT Tests probe the currently running app-owned strategy or scan selected official ALT BATs. For each ALT, fixed YouTube, Discord, Google, and Cloudflare addresses run concurrently, with HTTP/1.1, TLS 1.2, and TLS 1.3 variants per address. `redirector.googlevideo.com` is intentionally excluded. Any HTTP response counts as a passed probe; this does not prove playback or Discord usability. Fast mode cancels remaining probes after the first required failure. One expandable result row per ALT shows service status, average response time, HTTP code, and detailed errors. New rows appear first without replacing earlier row elements.

## Safety and data boundaries

- Frontend passes strategy IDs, never arbitrary commands or paths. Resolve BATs inside the verified official managed release and launch via fixed system `cmd.exe` with normal UAC. Do not run the upstream test script; it can stop unrelated `winws.exe` processes.
- The BAT runner identifies owned processes and windows by launch relationship, PID, creation time, and canonical path. Hide its own winws console; do not close it or touch unrelated terminals or processes. GUI exit leaves a running strategy active.
- Scans use the app-owned process receipt and a protected restoration journal. Preserve and restore the prior running strategy or stopped state on completion, cancellation, and failure. Ambiguous process identity must block automatic stopping. Do not run a live scan merely for development checks if a user's strategy may be active.
- Engine updates download official release assets with origin, digest, size, and archive validation. Stage before stopping, retain rollback, restore only the prior mode, and never roll back from a partially deleted backup after commit. An installed zapret service blocks updates until safe service restoration exists.
- Keep user config, appearance assets, lists, GameFilter settings, fake payloads, logs, history, and recovery data. User data lives under `%LOCALAPPDATA%\ZapretGui`; managed engine under `%ProgramData%\ZapretGui`.
- A running process, WinDivert driver, or successful HTTP probe is insufficient for bypass acceptance. Verify video playback and seeking without VPN after GUI Start and after hiding its console.

## Build and release

- Rust toolchain is pinned to 1.90.0. Run `npm run build`, then from `src-tauri` run `cargo fmt --check`, `cargo check --offline --locked`, and `cargo test --offline --locked --lib`. Some Windows tests need ordinary access to the system temporary directory.
- Run `npm run package:windows` and `npm run verify:release` at the repository root. The NSIS installer is unsigned; attach the exact verified installer to the GitHub release separately from the source commit.
- Follow `docs/windows-test-plan.md` and `docs/release-checklist.md` for real Windows acceptance. Automated builds and tests do not establish live playback, scan restoration, update/rollback, UAC, or uninstall acceptance.
