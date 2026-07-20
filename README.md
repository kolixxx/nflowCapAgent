# nflowCapAgent

Host NetFlow/IPFIX export agent for **Windows** and **Linux**. Captures traffic on a local interface and sends **IPFIX** (recommended) or NetFlow v9 to an **nfcapd** collector (e.g. [nfsen-ng](https://github.com/mbolli/nfsen-ng)).

## Quick start (Windows, Stage 1)

1. Install [Npcap](https://npcap.com/) (WinPcap API-compatible mode).
2. Download **`agent/dist/win-x64/netflowAgent.exe`** and **`agent/dist/win-x64/config.toml`**.
3. Edit `config.toml` — set `collector.host` and `capture.interface`.
4. Run **as Administrator**:

```powershell
.\netflowAgent.exe --list-devices
.\netflowAgent.exe --check-config
.\netflowAgent.exe --config config.toml
```

## Documentation

- [Agent design & test plan](docs/netflowAgent-design.adoc)
- [Windows agent install](docs/netflowAgent-install-windows.adoc)
- [Linux agent install](docs/netflowAgent-install-linux.adoc)
- [How TCP flags are collected](docs/netflowAgent-tcp-flags.adoc)
- [Ansible deployment](docs/nfclowCapAgentAnsible.adoc)
- [Clean reinstall and v0.3.1 acceptance test](docs/clean-reinstall-v0.3.1.adoc)
- [nfsen-ng collector install (Ubuntu 24.04)](docs/nfsen-ng-install-ubuntu2404.adoc)

## Build from source (Windows)

Requires Rust, Visual Studio Build Tools, and [Npcap SDK](https://npcap.com/#download) extracted to `agent/vendor/npcap-sdk/`.

```powershell
cd agent
cargo build --release
```

## License

MIT OR Apache-2.0
