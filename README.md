# Secure Multi-Client Relay

A C TCP relay and Streamlit client for encrypted direct messages and broadcast.
The relay routes authenticated encrypted frames without decrypting message
payloads. The Python client uses the project's `relay_protocol.py` module and
the shared protocol key.

## Project files

The expected Raspberry Pi project layout is:

```text
secure-relay/
├── client/           # C client programs
├── config/           # Local shared key (never commit)
├── frontend/         # Streamlit app and relay_protocol.py
├── include/          # C headers
├── src/              # C relay implementation
├── tests/             # C tests
├── build/             # Compiled binaries (ignored)
└── Makefile
```

The `outputs/app.py` file is the current chat-style Streamlit frontend. Copy it
to `frontend/app.py` in the complete project, alongside the existing
`frontend/relay_protocol.py`.

## Run on Raspberry Pi

Start the relay in one terminal:

```bash
cd ~/secure-relay
./build/relay_server
```

Start Streamlit in another terminal:

```bash
cd ~/secure-relay
frontend/venv/bin/streamlit run frontend/app.py --server.address 0.0.0.0 --server.port 8501
```

Open `http://192.168.2.2:8501` from a device on the same network. The default
relay address is `192.168.2.2:9090`; the frontend expects
`config/shared.key` in the project's existing 64-hex-character format.

## Git safety

The `.gitignore` excludes shared keys, Python virtual environments and caches,
and generated build output. Review `git status` before committing to ensure no
credentials or private keys are staged.
