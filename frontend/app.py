"""Streamlit client for the secure multi-client relay.

This UI is a real client: it encrypts locally, sends protocol frames over TCP,
and decrypts only frames delivered to this client by the blind C relay.
"""

from __future__ import annotations

import queue
import socket
import struct
import threading
import time
import html
from dataclasses import dataclass
from pathlib import Path

import streamlit as st

from relay_protocol import (
    CRYPTO_MAC_SIZE,
    CRYPTO_NONCE_SIZE,
    CRYPTO_KEY_SIZE,
    PROTOCOL_BROADCAST_ID,
    PROTOCOL_HEADER_SIZE,
    PROTOCOL_MAX_PAYLOAD,
    PROTOCOL_TYPE_CLIENT_ID,
    PROTOCOL_TYPE_MESSAGE,
    PROTOCOL_VERSION,
    build_message_frame,
    decrypt_message,
    load_key,
    parse_frame,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SERVER_HOST = "192.168.2.2"
DEFAULT_SERVER_PORT = 9090
DEFAULT_KEY_PATH = PROJECT_ROOT / "config" / "shared.key"


def recv_exact(sock: socket.socket, length: int) -> bytes:
    """Read exactly *length* bytes; TCP does not preserve frame boundaries."""
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Relay closed the connection")
        data.extend(chunk)
    return bytes(data)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive and validate one 46-byte-header relay frame."""
    header = recv_exact(sock, PROTOCOL_HEADER_SIZE)
    frame_type = header[1]
    ciphertext_length = struct.unpack_from(">I", header, 18)[0]

    if frame_type == PROTOCOL_TYPE_CLIENT_ID:
        if ciphertext_length != 0:
            raise ValueError("Client-ID control frame has a payload")
        return header
    if frame_type != PROTOCOL_TYPE_MESSAGE:
        raise ValueError(f"Unsupported protocol frame type: {frame_type}")
    if not CRYPTO_MAC_SIZE <= ciphertext_length <= PROTOCOL_MAX_PAYLOAD + CRYPTO_MAC_SIZE:
        raise ValueError("Invalid encrypted payload length")
    return header + recv_exact(sock, ciphertext_length)


@dataclass(frozen=True)
class SessionEvent:
    when: float
    kind: str
    detail: str


class RelayConnection:
    """One lifecycle-managed relay TCP connection for a Streamlit browser session."""

    def __init__(self) -> None:
        self._socket: socket.socket | None = None
        self._receiver: threading.Thread | None = None
        self._running = threading.Event()
        self._lock = threading.RLock()
        self._events: queue.Queue[dict] = queue.Queue()
        self.connected = False
        self.client_id: int | None = None
        self.key: bytes | None = None
        self.next_sequence = 1
        self.connected_at: float | None = None
        self.sent_messages = 0
        self.received_messages = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.known_peers: set[int] = set()
        self.activity: list[SessionEvent] = []
        self.messages: list[dict] = []

    def _record(self, kind: str, detail: str) -> None:
        self._events.put({"when": time.time(), "kind": kind, "detail": detail})

    def drain_events(self) -> None:
        """Move receiver events into UI-owned collections during a Streamlit run."""
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                return
            with self._lock:
                self.activity.append(SessionEvent(event["when"], event["kind"], event["detail"]))
                self.activity = self.activity[-200:]
                if event["kind"] == "message":
                    self.messages.append(event)
                    self.messages = self.messages[-200:]

    def connect(self, host: str, port: int, key: bytes) -> None:
        self.disconnect(reason="Reconnecting")
        sock = socket.create_connection((host, port), timeout=10)
        sock.settimeout(None)
        with self._lock:
            self._socket = sock
            self.key = key
            self.connected = True
            self.client_id = None
            self.next_sequence = 1
            self.connected_at = time.time()
            self.sent_messages = self.received_messages = 0
            self.bytes_sent = self.bytes_received = 0
            self.known_peers.clear()
            self.messages.clear()
            self.activity.clear()
            self._running.set()
        self._receiver = threading.Thread(target=self._receive_loop, name="relay-receiver", daemon=True)
        self._receiver.start()
        self._record("connected", f"Connected to {host}:{port}; awaiting assigned client ID")

    def _receive_loop(self) -> None:
        try:
            while self._running.is_set():
                with self._lock:
                    sock = self._socket
                    key = self.key
                if sock is None or key is None:
                    return
                frame = recv_frame(sock)
                info = parse_frame(frame)
                with self._lock:
                    self.bytes_received += len(frame)
                if info["type"] == PROTOCOL_TYPE_CLIENT_ID:
                    assigned_id = info["target_id"]
                    with self._lock:
                        self.client_id = assigned_id
                    self._record("assigned", f"Relay assigned local client ID #{assigned_id}")
                    continue
                info, plaintext = decrypt_message(key, frame)
                text = plaintext.decode("utf-8", errors="replace")
                with self._lock:
                    self.received_messages += 1
                    self.known_peers.add(info["sender_id"])
                destination = "broadcast" if info["target_id"] == PROTOCOL_BROADCAST_ID else f"client #{info['target_id']}"
                self._events.put({
                    "when": time.time(), "kind": "message", "direction": "received",
                    "sender_id": info["sender_id"], "target_id": info["target_id"],
                    "sequence": info["sequence"], "text": text, "bytes": len(frame),
                    "detail": f"Received authenticated encrypted message from #{info['sender_id']} to {destination} (sequence {info['sequence']})",
                })
        except Exception as exc:
            if self._running.is_set():
                self._record("error", f"Receive loop stopped: {exc}")
        finally:
            with self._lock:
                self.connected = False
            self._running.clear()

    def send_message(self, target_id: int, text: str) -> None:
        plaintext = text.encode("utf-8")
        if not plaintext:
            raise ValueError("Message cannot be empty")
        if len(plaintext) > PROTOCOL_MAX_PAYLOAD:
            raise ValueError(f"Message exceeds {PROTOCOL_MAX_PAYLOAD} UTF-8 bytes")
        with self._lock:
            if not self.connected or self._socket is None or self.key is None:
                raise ConnectionError("Not connected to the relay")
            if self.client_id is None:
                raise RuntimeError("The relay has not assigned this client an ID yet")
            sequence = self.next_sequence
            frame = build_message_frame(self.key, self.client_id, target_id, sequence, plaintext)
            self._socket.sendall(frame)
            self.next_sequence += 1
            self.sent_messages += 1
            self.bytes_sent += len(frame)
        destination = "broadcast" if target_id == PROTOCOL_BROADCAST_ID else f"client #{target_id}"
        self._events.put({
            "when": time.time(), "kind": "message", "direction": "sent",
            "sender_id": self.client_id, "target_id": target_id, "sequence": sequence,
            "text": text, "bytes": len(frame),
            "detail": f"Sent authenticated encrypted message to {destination} (sequence {sequence})",
        })

    def disconnect(self, reason: str = "Disconnected by user") -> None:
        was_active = self._running.is_set() or self.connected
        self._running.clear()
        with self._lock:
            sock, self._socket = self._socket, None
            self.connected = False
            self.client_id = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        receiver = self._receiver
        if receiver is not None and receiver is not threading.current_thread():
            receiver.join(timeout=1)
        if was_active:
            self._record("disconnected", reason)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "connected": self.connected, "client_id": self.client_id,
                "sent": self.sent_messages, "received": self.received_messages,
                "bytes_sent": self.bytes_sent, "bytes_received": self.bytes_received,
                "connected_at": self.connected_at, "peers": sorted(self.known_peers),
            }


def connection() -> RelayConnection:
    if "relay_connection" not in st.session_state:
        st.session_state.relay_connection = RelayConnection()
    return st.session_state.relay_connection


def fmt_bytes(value: int) -> str:
    return f"{value:,} B"


def uptime(connected_at: float | None) -> str:
    if connected_at is None:
        return "—"
    seconds = max(0, int(time.time() - connected_at))
    return f"{seconds // 3600:02}:{(seconds % 3600) // 60:02}:{seconds % 60:02}"


def chat_name(target: int) -> str:
    return "Broadcast" if target == PROTOCOL_BROADCAST_ID else f"Client #{target}"


def conversation_for(messages: list[dict], target: int, local_client_id: int | None) -> list[dict]:
    """Messages this browser session sent to, or received in, one conversation."""
    conversation = []
    for message in messages:
        if message["direction"] == "sent" and message["target_id"] == target:
            conversation.append(message)
        elif message["direction"] == "received":
            is_broadcast = target == 0 and message["target_id"] == 0
            is_direct_to_this_client = (
                target != 0
                and message["sender_id"] == target
                and message["target_id"] == local_client_id
            )
            if is_broadcast or is_direct_to_this_client:
                conversation.append(message)
    return conversation


def conversation_preview(conversation: list[dict]) -> str:
    """Return a real, short preview for one locally observed conversation."""
    if not conversation:
        return "No messages yet"
    message = conversation[-1]
    text = f"You: {message['text']}" if message["direction"] == "sent" else message["text"]
    text = " ".join(text.split())
    return text[:40] + ("…" if len(text) > 40 else "")


def received_count(conversation: list[dict]) -> int:
    return sum(1 for message in conversation if message["direction"] == "received")


def last_error(relay: RelayConnection) -> str | None:
    """The most recent receive error, if it happened after the last connect."""
    for event in reversed(relay.activity):
        if event.kind == "error":
            return event.detail
        if event.kind == "connected":
            return None
    return None


LOGO_SVG = (
    '<svg class="rc-logo" viewBox="0 0 32 32" width="32" height="32" aria-hidden="true">'
    '<rect x="1" y="1" width="30" height="30" rx="8" fill="#161F30" stroke="#334155"/>'
    '<path d="M21.5 10.5h-9a3 3 0 0 0 0 6h7a3 3 0 0 1 0 6h-9" fill="none" stroke="#F8FAFC" '
    'stroke-width="3" stroke-linecap="round"/></svg>'
)
LOCK_SVG = (
    '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><rect x="3" y="7" width="10" height="7" '
    'rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2" '
    'fill="none" stroke="currentColor" stroke-width="1.5"/></svg>'
)
CHECK_SVG = (
    '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true"><circle cx="8" cy="8" r="6.25" fill="none" '
    'stroke="currentColor" stroke-width="1.5"/><path d="M5.3 8.2l1.8 1.8 3.6-3.8" fill="none" stroke="currentColor" '
    'stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
SHIELD_SVG = (
    '<svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true"><path d="M8 1.5l5 2v4.2c0 3.1-2.1 5.6-5 6.8'
    '-2.9-1.2-5-3.7-5-6.8V3.5z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"/></svg>'
)


def style() -> None:
    st.html("""<style>
    @import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
    :root {
        --void: #0B0F17; --base: #111827; --raised: #161F30; --line: #1E293B; --line-strong: #334155;
        --text: #F8FAFC; --text-2: #94A3B8; --muted: #64748B;
        --blue: #0EA5E9; --blue-hi: #38BDF8; --green: #10B981; --green-hi: #34D399;
        --amber: #F59E0B; --amber-hi: #FBBF24; --red: #EF4444; --red-hi: #F87171;
        --sans: 'Geist', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        --mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .stApp { background: var(--void); color: var(--text); font-family: var(--sans); }
    .stApp p, .stApp label, .stApp input, .stApp textarea, .stApp button { font-family: var(--sans); }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stAppDeployButton"], .stAppDeployButton, [data-testid="stDecoration"] { display: none; }
    [data-testid="stMainBlockContainer"] { padding: 1.4rem 2rem 1.5rem; max-width: 1280px; }
    [data-testid="stSidebar"] { background: var(--base); border-right: 1px solid var(--line); }
    [data-testid="stSidebarContent"] { padding-top: .25rem; }
    [data-testid="stSidebarUserContent"] { padding: 0 1rem 1.5rem; }
    [data-testid="stSidebarHeader"] { padding-bottom: 0; margin-bottom: 0; height: 2.75rem; }

    /* inputs and buttons */
    [data-baseweb="input"], [data-baseweb="base-input"], [data-testid="stNumberInputContainer"] {
        background: var(--void) !important; border-color: var(--line) !important; border-radius: 8px; }
    [data-baseweb="input"] input { font-family: var(--mono); font-size: 13px; color: var(--text); }
    [data-testid="stWidgetLabel"] p { font-family: var(--mono); font-size: 10.5px; letter-spacing: .08em;
        text-transform: uppercase; color: var(--text-2); }
    .stButton > button { border-radius: 8px; font-weight: 600; min-height: 36px; }
    .stButton > button[kind="primary"] { background: var(--blue); border: 1px solid var(--blue-hi); color: var(--void); }
    .stButton > button[kind="primary"]:hover { background: var(--blue-hi); color: var(--void);
        box-shadow: 0 0 0 1px var(--blue), 0 0 12px rgba(14,165,233,.25); }
    .stButton > button[kind="secondary"] { background: var(--raised); border: 1px solid var(--line); color: var(--text); }
    .stButton > button[kind="secondary"]:hover { border-color: var(--line-strong); color: var(--blue-hi); }
    [data-testid="stExpander"] details { background: transparent; border: 1px solid var(--line); border-radius: 10px; }
    [data-testid="stExpander"] summary p { font-size: 13px; font-weight: 600; }
    [data-testid="stSidebar"] hr { border-color: var(--line); margin: .9rem 0; }

    /* shared atoms */
    .rc-label { font-family: var(--mono); font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase;
        color: var(--muted); display: flex; align-items: center; gap: .45rem; }
    .rc-count { background: var(--raised); color: var(--text-2); border-radius: 4px; padding: 0 .35rem; }
    .rc-chip { font-family: var(--mono); font-size: 10.5px; letter-spacing: .06em; text-transform: uppercase;
        border: 1px solid var(--line-strong); color: var(--text-2); background: var(--raised);
        border-radius: 4px; padding: .2rem .5rem; display: inline-flex; align-items: center; gap: .35rem; white-space: nowrap; }
    .rc-chip.green { border-color: rgba(16,185,129,.4); background: rgba(16,185,129,.08); color: var(--green-hi); }
    .rc-chip.blue { border-color: rgba(14,165,233,.4); background: rgba(14,165,233,.08); color: var(--blue-hi); }
    .rc-chip.amber { border-color: rgba(245,158,11,.4); background: rgba(245,158,11,.08); color: var(--amber-hi); }
    .rc-chip.red { border-color: rgba(239,68,68,.4); background: rgba(239,68,68,.08); color: var(--red-hi); }
    .rc-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; display: inline-block; }
    .rc-chip.green .rc-dot { animation: rc-pulse 2s ease-in-out infinite; }
    @keyframes rc-pulse { 0%, 100% { opacity: 1; } 50% { opacity: .35; } }

    /* sidebar brand + channel list */
    .rc-brand { display: flex; gap: .7rem; align-items: center; padding: .4rem 0 .2rem; }
    .rc-brand-name { font-size: 13px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--text); }
    .rc-brand-tag { font-size: 12px; color: var(--muted); }
    .rc-brand-chip { margin-top: .7rem; }
    .st-key-channels, .st-key-channels [data-testid="stVerticalBlock"] { gap: 0; }
    .st-key-channels [data-testid="stMarkdownContainer"] { margin-bottom: 0; }
    .st-key-channels .stButton > button { justify-content: flex-start; background: transparent; border: 0;
        border-left: 2px solid transparent; border-radius: 6px; color: var(--text-2); font-weight: 500;
        min-height: 34px; padding: .3rem .6rem; }
    .st-key-channels .stButton > button > div { justify-content: flex-start; width: 100%; }
    .st-key-channels .stButton > button:hover { background: var(--raised); color: var(--text); }
    .st-key-channels .stButton > button[kind="primary"] { background: var(--raised); color: var(--text);
        border-left-color: var(--blue); box-shadow: none; }
    .st-key-channels .stButton > button p { font-family: var(--mono); font-size: 13px; }
    .rc-preview { display: flex; justify-content: space-between; gap: .5rem; padding: .05rem .6rem .7rem 2.05rem;
        font-size: 12px; color: var(--muted); }
    .rc-preview span:first-child { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .rc-unread { background: var(--blue); color: var(--void); font-family: var(--mono); font-size: 10px;
        font-weight: 700; border-radius: 9px; padding: 0 .4rem; line-height: 16px; height: 16px; }

    /* chat header */
    .rc-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
    .rc-title { font-size: 26px; font-weight: 600; letter-spacing: -.02em; line-height: 1.15; color: var(--text); }
    .rc-subtitle { font-family: var(--mono); font-size: 11.5px; color: var(--muted); margin-top: .2rem; }
    .rc-header-chips { display: flex; gap: .45rem; flex-wrap: wrap; justify-content: flex-end; padding-top: .3rem; }
    .rc-strip { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); margin: .9rem 0 0;
        background: var(--base); border: 1px solid var(--line); border-radius: 10px; }
    .rc-strip > div { padding: .6rem .8rem; border-right: 1px solid var(--line); min-width: 0; }
    .rc-strip > div:last-child { border-right: 0; }
    .rc-strip b { display: block; font-family: var(--mono); font-size: 9.5px; font-weight: 500; letter-spacing: .1em;
        text-transform: uppercase; color: var(--muted); margin-bottom: .15rem; }
    .rc-strip span { font-family: var(--mono); font-size: 12px; color: var(--text); white-space: nowrap;
        overflow: hidden; text-overflow: ellipsis; display: block; }
    .rc-strip .ok { color: var(--green-hi); }

    /* message pane */
    .rc-pane { background: var(--base); border: 1px solid var(--line); border-radius: 10px; margin-top: .9rem;
        height: calc(100vh - 480px); min-height: 260px; overflow-y: auto; display: flex; flex-direction: column-reverse;
        padding: .5rem 1.6rem 1.2rem; }
    .rc-pane-inner { display: flex; flex-direction: column; gap: 1.1rem; }
    .rc-divider { display: flex; align-items: center; gap: 1rem; font-family: var(--mono); font-size: 10.5px;
        letter-spacing: .14em; color: var(--muted); text-transform: uppercase; margin: 1rem 0 .2rem; }
    .rc-divider::before, .rc-divider::after { content: ""; flex: 1; border-top: 1px solid var(--line-strong); }
    .rc-msg-head { display: flex; align-items: baseline; gap: .6rem; font-family: var(--mono); font-size: 11px;
        color: var(--muted); margin-bottom: .35rem; }
    .rc-msg-head .who { font-weight: 700; letter-spacing: .06em; text-transform: uppercase; color: var(--text); font-size: 11.5px; }
    .rc-msg.out .rc-msg-head .who { color: var(--blue-hi); }
    .rc-msg-head .time { color: var(--text-2); }
    .rc-msg-body { background: var(--raised); border: 1px solid var(--line); border-left: 2px solid var(--line-strong);
        border-radius: 6px; padding: .7rem .9rem; font-size: 15px; line-height: 1.5; color: var(--text);
        white-space: pre-wrap; overflow-wrap: anywhere; max-width: 860px; }
    .rc-msg.out .rc-msg-body { border-left-color: var(--blue); }
    .rc-msg.in .rc-msg-body { border-left-color: var(--green); }
    .rc-msg.bc .rc-msg-body { border-left-color: var(--amber); }
    .rc-msg-meta { display: flex; flex-wrap: wrap; align-items: center; gap: .45rem; margin-top: .4rem;
        font-family: var(--mono); font-size: 11px; color: var(--muted); }
    .rc-msg-meta .ok { color: var(--green-hi); display: inline-flex; align-items: center; gap: .3rem; }
    .rc-msg-meta .sep { color: var(--line-strong); }
    .rc-empty { margin: auto; text-align: center; color: var(--text-2); max-width: 420px; padding: 2rem 1rem; }
    .rc-empty .icon { width: 44px; height: 44px; border-radius: 10px; margin: 0 auto .9rem; display: grid; place-items: center;
        background: var(--raised); border: 1px solid var(--line-strong); color: var(--text-2); }
    .rc-empty .icon svg { width: 20px; height: 20px; }
    .rc-empty-title { font-size: 17px; font-weight: 600; color: var(--text); margin: 0 0 .35rem; }
    .rc-empty p { font-size: 13.5px; line-height: 1.55; margin: 0; }
    .rc-empty .err { margin-top: .9rem; font-family: var(--mono); font-size: 11.5px; color: var(--red-hi); }

    /* offline / handshake card */
    .st-key-offline { background: var(--base); border: 1px solid var(--line); margin-top: .9rem;
        border-radius: 10px; padding: 3rem 1rem 3.2rem; }
    .st-key-offline .rc-empty { padding: 0; margin: 0 auto; }
    .st-key-connect-main { margin: 1.2rem auto 0; }
    .st-key-connect-main button { min-width: 260px; }

    /* composer */
    .rc-composer-head { display: flex; justify-content: space-between; align-items: center; margin: 1rem 0 .45rem;
        font-family: var(--mono); font-size: 11px; color: var(--muted); }
    .rc-composer-head .to { letter-spacing: .1em; text-transform: uppercase; color: var(--text-2); font-weight: 600; }
    .rc-kbd { border: 1px solid var(--line-strong); background: var(--raised); border-radius: 4px; padding: 0 .35rem; color: var(--text-2); }
    [data-testid="stChatInput"] { background: var(--void); border: 1px solid var(--line-strong); border-radius: 10px; }
    [data-testid="stChatInput"]:focus-within { border-color: var(--blue); box-shadow: 0 0 0 1px var(--blue); }
    [data-testid="stChatInput"] textarea { font-size: 14.5px; color: var(--text); }
    [data-testid="stChatInputSubmitButton"] { color: var(--blue-hi); }
    .rc-footer { display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin: .55rem 0 .9rem;
        font-family: var(--mono); font-size: 11px; color: var(--muted); }
    .rc-footer .note { display: inline-flex; align-items: center; gap: .4rem; color: var(--text-2); font-family: var(--sans); font-size: 12.5px; }
    .rc-footer .note svg { color: var(--green-hi); }
    .rc-footer .stats { display: flex; gap: .9rem; }
    .rc-footer .stats b { color: var(--text-2); font-weight: 500; }

    /* session log */
    .rc-log { font-family: var(--mono); font-size: 11.5px; line-height: 1.5; }
    .rc-log div { display: grid; grid-template-columns: 70px 92px 1fr; gap: .6rem; padding: .25rem 0; border-bottom: 1px solid var(--line); }
    .rc-log div:last-child { border-bottom: 0; }
    .rc-log .t { color: var(--muted); }
    .rc-log .k { text-transform: uppercase; letter-spacing: .06em; color: var(--text-2); }
    .rc-log .k.error { color: var(--red-hi); } .rc-log .k.assigned, .rc-log .k.connected { color: var(--green-hi); }
    .rc-log .k.disconnected { color: var(--amber-hi); }
    .rc-log .d { color: var(--text); overflow-wrap: anywhere; }

    @media (max-width: 900px) {
        [data-testid="stMainBlockContainer"] { padding: 1rem 1rem 1.5rem; }
        .rc-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .rc-strip > div:nth-child(3) { border-right: 0; }
        .rc-strip > div:nth-child(-n+3) { border-bottom: 1px solid var(--line); }
        .rc-pane { padding: .5rem .9rem 1rem; }
    }
    </style>""")


def show(markup: str) -> None:
    """Render trusted UI markup; every user-supplied value is escaped before it gets here."""
    st.markdown(markup, unsafe_allow_html=True)


def message_html(message: dict) -> str:
    outgoing = message["direction"] == "sent"
    classes = "rc-msg " + ("out" if outgoing else "in") + (" bc" if message["target_id"] == 0 else "")
    who = "You" if outgoing else f"Client #{message['sender_id']}"
    when = time.strftime("%H:%M:%S", time.localtime(message["when"]))
    tag = "TX_OUT" if outgoing else "RX_IN"
    broadcast = '<span class="rc-chip amber">Broadcast</span>' if message["target_id"] == 0 and outgoing else ""
    if outgoing:
        status = f'<span class="ok">{LOCK_SVG}Encrypted</span><span class="sep">·</span><span>Sent to relay</span>'
    else:
        status = f'<span class="ok">{CHECK_SVG}Decrypted</span><span class="sep">·</span><span>MAC verified</span>'
    body = html.escape(message["text"]).replace("\n", "<br>")
    return (
        f'<div class="{classes}">'
        f'<div class="rc-msg-head"><span class="who">{html.escape(who)}</span><span class="time">{when}</span>'
        f'<span>{tag}</span>{broadcast}</div>'
        f'<div class="rc-msg-body">{body}</div>'
        f'<div class="rc-msg-meta">{status}<span class="sep">·</span><span>{message["bytes"]} B frame</span>'
        f'<span class="sep">·</span><span>Seq #{message["sequence"]}</span></div>'
        f'</div>'
    )


def empty_html(icon: str, title: str, body: str, error: str | None = None) -> str:
    error_html = f'<div class="err">{html.escape(error)}</div>' if error else ""
    return (
        f'<div class="rc-empty"><div class="icon">{icon}</div><div class="rc-empty-title">{html.escape(title)}</div>'
        f'<p>{html.escape(body)}</p>{error_html}</div>'
    )


def relay_address() -> str:
    host = st.session_state.get("host", st.session_state.get("cfg_host", DEFAULT_SERVER_HOST))
    port = st.session_state.get("port", st.session_state.get("cfg_port", DEFAULT_SERVER_PORT))
    return f"{host}:{port}"


def connect_from_settings(relay: RelayConnection) -> None:
    host = st.session_state.cfg_host.strip()
    port = int(st.session_state.cfg_port)
    key_path = st.session_state.cfg_key_path
    try:
        relay.connect(host, port, load_key(key_path))
        st.session_state.update(host=host, port=port, key_path=key_path)
        st.session_state.connect_error = None
    except (OSError, ValueError, ConnectionError) as exc:
        st.session_state.connect_error = f"Could not connect to {host}:{port}: {exc}"


@st.fragment(run_every=2)
def render_live_chat(relay: RelayConnection) -> None:
    """Refresh only the chat fragment every two seconds, never the full app."""
    relay.drain_events()
    state = relay.snapshot()
    target = st.session_state.active_target
    name = chat_name(target)
    conversation = conversation_for(relay.messages, target, state["client_id"])
    st.session_state.seen[target] = received_count(conversation)

    if state["connected"] and state["client_id"] is not None:
        presence = '<span class="rc-chip green"><span class="rc-dot"></span>Online</span>'
    elif state["connected"]:
        presence = '<span class="rc-chip amber"><span class="rc-dot"></span>Handshaking</span>'
    else:
        presence = '<span class="rc-chip red"><span class="rc-dot"></span>Offline</span>'
    you = f"You: Client #{state['client_id']}" if state["connected"] and state["client_id"] is not None else "You: unassigned"
    subtitle = "All connected peers" if target == 0 else "Direct, end-to-end encrypted"
    show(
        f'<div class="rc-header"><div><div class="rc-title">{name}</div>'
        f'<div class="rc-subtitle">{subtitle} · relay {html.escape(relay_address())}</div></div>'
        f'<div class="rc-header-chips">{presence}<span class="rc-chip blue">{html.escape(you)}</span>'
        f'<span class="rc-chip">{LOCK_SVG}XChaCha20-Poly1305</span></div></div>'
        f'<div class="rc-strip">'
        f'<div><b>Cipher</b><span>XChaCha20-Poly1305-IETF</span></div>'
        f'<div><b>MAC</b><span>Poly1305 · {CRYPTO_MAC_SIZE} B</span></div>'
        f'<div><b>Nonce</b><span>{CRYPTO_NONCE_SIZE} B random</span></div>'
        f'<div><b>Key</b><span class="ok">{CRYPTO_KEY_SIZE * 8}-bit shared</span></div>'
        f'<div><b>Next seq</b><span>{"#" + str(relay.next_sequence) if state["connected"] else "—"}</span></div>'
        f'<div><b>Uptime</b><span>{uptime(state["connected_at"]) if state["connected"] else "—"}</span></div>'
        f'</div>'
    )

    if not state["connected"] or state["client_id"] is None:
        with st.container(key="offline"):
            if not state["connected"]:
                error = last_error(relay) or st.session_state.get("connect_error")
                show(empty_html(
                    SHIELD_SVG, "Relay offline",
                    f"Connect to the relay at {relay_address()} to start an encrypted session. "
                    "Messages are encrypted on this device before they leave it.",
                    error,
                ))
                if st.button(f"Connect to {relay_address()}", type="primary", key="connect-main"):
                    connect_from_settings(relay)
                    st.rerun()
            else:
                show(empty_html(
                    SHIELD_SVG, "Handshaking with the relay",
                    "Connected. Waiting for the relay to assign this browser session a client ID.",
                ))
    else:
        if conversation:
            items = '<div class="rc-divider">Secure session established</div>'
            items += "".join(message_html(message) for message in conversation)
        else:
            body = (
                "Broadcasts reach every client connected to the relay."
                if target == 0 else f"Messages you send to Client #{target} are readable only by them."
            )
            items = empty_html(LOCK_SVG, f"No messages with {name} yet" if target else "No broadcasts yet", body)
        show(f'<div class="rc-pane"><div class="rc-pane-inner">{items}</div></div>')

        show(
            f'<div class="rc-composer-head"><span class="to">To: {name}</span>'
            f'<span>Press <span class="rc-kbd">Enter</span> to send</span></div>'
        )
        text = st.chat_input(f"Write an encrypted message to {name}…", max_chars=PROTOCOL_MAX_PAYLOAD)
        if text:
            try:
                relay.send_message(target, text)
                relay.drain_events()
                st.rerun(scope="fragment")
            except (ValueError, RuntimeError, ConnectionError, OSError) as exc:
                st.error(str(exc))

    total_bytes = fmt_bytes(state["bytes_sent"] + state["bytes_received"])
    show(
        f'<div class="rc-footer"><span class="note">{SHIELD_SVG}Payloads are encrypted locally. '
        f'The relay never sees plaintext.</span>'
        f'<span class="stats"><span>TX <b>{state["sent"]}</b></span><span>RX <b>{state["received"]}</b></span>'
        f'<span>Traffic <b>{total_bytes}</b></span><span>Live · 2s</span></span></div>'
    )

    with st.expander(f"Session log · {len(relay.activity)} events"):
        if relay.activity:
            rows = "".join(
                f'<div><span class="t">{time.strftime("%H:%M:%S", time.localtime(event.when))}</span>'
                f'<span class="k {html.escape(event.kind)}">{html.escape(event.kind)}</span>'
                f'<span class="d">{html.escape(event.detail)}</span></div>'
                for event in reversed(relay.activity[-40:])
            )
            show(f'<div class="rc-log">{rows}</div>')
        else:
            st.caption("No session events yet.")


@st.fragment(run_every=2)
def render_channels(relay: RelayConnection) -> None:
    """Live channel list: broadcast plus every peer this session has heard from."""
    relay.drain_events()
    state = relay.snapshot()
    active = st.session_state.active_target
    targets = [0] + state["peers"]
    if active not in targets:
        targets.append(active)
    show(f'<div class="rc-label">Channels <span class="rc-count">{len(targets)}</span></div>')
    with st.container(key="channels"):
        for target in targets:
            icon = ":material/cell_tower:" if target == 0 else ":material/person:"
            if st.button(
                chat_name(target), key=f"channel-{target}", icon=icon, use_container_width=True,
                type="primary" if target == active else "secondary",
            ):
                st.session_state.active_target = target
                st.rerun()
            conversation = conversation_for(relay.messages, target, state["client_id"])
            unread = 0 if target == active else max(0, received_count(conversation) - st.session_state.seen.get(target, 0))
            badge = f'<span class="rc-unread">{unread}</span>' if unread else ""
            show(
                f'<div class="rc-preview"><span>{html.escape(conversation_preview(conversation))}</span>{badge}</div>'
            )


def main() -> None:
    st.set_page_config(page_title="Relay Chat", page_icon="🔐", layout="wide")
    style()
    relay = connection()
    relay.drain_events()
    state = relay.snapshot()
    st.session_state.setdefault("active_target", 0)
    st.session_state.setdefault("seen", {})
    st.session_state.setdefault("cfg_host", st.session_state.get("host", DEFAULT_SERVER_HOST))
    st.session_state.setdefault("cfg_port", int(st.session_state.get("port", DEFAULT_SERVER_PORT)))
    st.session_state.setdefault("cfg_key_path", st.session_state.get("key_path", str(DEFAULT_KEY_PATH)))

    with st.sidebar:
        show(
            f'<div class="rc-brand">{LOGO_SVG}<div><div class="rc-brand-name">Relay Chat</div>'
            f'<div class="rc-brand-tag">Route securely. Reveal nothing.</div></div></div>'
            f'<div class="rc-brand-chip"><span class="rc-chip">{LOCK_SVG}Blind encrypted relay</span></div>'
        )
        st.divider()
        render_channels(relay)

        show('<div class="rc-label" style="margin-top:.6rem">New direct chat</div>')
        id_col, open_col = st.columns([3, 2], vertical_alignment="bottom")
        new_target = id_col.number_input(
            "Client ID", min_value=1, max_value=0xFFFFFFFF, value=1, step=1, label_visibility="collapsed"
        )
        if open_col.button("Open", use_container_width=True):
            st.session_state.active_target = int(new_target)
            st.rerun()
        st.divider()

        with st.expander("Connection", icon=":material/lan:", expanded=not state["connected"]):
            st.text_input("Relay host", key="cfg_host")
            st.number_input("TCP port", min_value=1, max_value=65535, step=1, key="cfg_port")
            st.text_input("Shared key path", key="cfg_key_path")
            if state["connected"]:
                if st.button("Disconnect", use_container_width=True):
                    relay.disconnect()
                    relay.drain_events()
                    st.rerun()
            elif st.button("Connect to relay", type="primary", use_container_width=True):
                connect_from_settings(relay)
                st.rerun()
        with st.expander("Security model", icon=":material/shield:"):
            st.caption(
                "XChaCha20-Poly1305-IETF · 32-byte key · 24-byte nonce · 16-byte MAC · authenticated routing "
                "metadata. The C relay validates sender IDs and strict incoming sequence numbers, and does not "
                "decrypt payloads."
            )

    render_live_chat(relay)


if __name__ == "__main__":
    main()
