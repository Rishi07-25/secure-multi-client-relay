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


def conversation_preview(messages: list[dict], target: int, local_client_id: int | None) -> str:
    """Return a real, short preview for one locally observed conversation."""
    for message in reversed(messages):
        if message["direction"] == "sent" and message["target_id"] == target:
            text = f"You: {message['text']}"
            return text[:42] + ("…" if len(text) > 42 else "")
        if message["direction"] == "received":
            is_broadcast = target == 0 and message["target_id"] == 0
            is_direct = (
                target != 0
                and message["sender_id"] == target
                and message["target_id"] == local_client_id
            )
            if is_broadcast or is_direct:
                text = message["text"]
                return text[:42] + ("…" if len(text) > 42 else "")
    return "No messages yet"


def style() -> None:
    st.markdown("""<style>
    .stApp { background: #0b141a; color: #e9edef; }
    [data-testid="stSidebar"] { background: #111b21; border-right: 1px solid #27363d; }
    [data-testid="stSidebar"] .stButton > button { justify-content: flex-start; background: transparent; border: 0; color: #e9edef; }
    [data-testid="stSidebar"] .stButton > button:hover { background: #202c33; }
    .chat-title { font-size: 1.25rem; font-weight: 650; color: #e9edef; margin-bottom: .1rem; }
    .chat-subtitle { color: #8696a0; font-size: .88rem; }
    .topbar { background: #202c33; border-radius: 8px; padding: .75rem 1rem; margin-bottom: 1rem; }
    .topbar-name { font-size: 1.08rem; font-weight: 650; color: #e9edef; }
    .topbar-meta { color: #00a884; font-size: .83rem; }
    .empty-chat { color: #8696a0; text-align: center; padding: 4.5rem 1rem; }
    .conversation-preview { color: #8696a0; font-size: .74rem; margin: -.45rem .35rem .5rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .message-row { display: flex; width: 100%; margin: .35rem 0; }
    .message-row.outgoing { justify-content: flex-end; }
    .message-row.incoming { justify-content: flex-start; }
    .message-bubble { max-width: min(78%, 720px); border-radius: 9px; padding: .55rem .7rem .4rem; line-height: 1.35; }
    .message-bubble.outgoing { background: #005c4b; color: #eefbf7; border-top-right-radius: 2px; }
    .message-bubble.incoming { background: #202c33; color: #e9edef; border-top-left-radius: 2px; }
    .message-bubble.broadcast { border-left: 3px solid #f5b942; }
    .message-meta { color: #b9d9d0; font-size: .7rem; text-align: right; margin-top: .3rem; }
    .message-bubble.incoming .message-meta { color: #9eb2bb; }
    .chat-divider { color: #8696a0; font-size: .75rem; text-align: center; margin: 1.2rem 0 .8rem; }
    .session-note { color: #8696a0; font-size: .78rem; text-align: center; margin-top: .5rem; }
    </style>""", unsafe_allow_html=True)


@st.fragment(run_every=2)
def render_live_chat(relay: RelayConnection) -> None:
    """Refresh only the chat fragment every two seconds, never the full app."""
    relay.drain_events()
    state = relay.snapshot()
    target = st.session_state.active_target
    chat_name = "Broadcast" if target == 0 else f"Client #{target}"
    presence = "Connected" if state["connected"] else "Disconnected"
    client_label = f"#{state['client_id']}" if state["client_id"] is not None else "awaiting assignment"
    st.markdown(f'<div class="topbar"><div class="topbar-name">{chat_name}</div><div class="topbar-meta">{presence} · encrypted relay · your client ID: {client_label}</div></div>', unsafe_allow_html=True)

    conversation = []
    for message in relay.messages:
        if message["direction"] == "sent" and message["target_id"] == target:
            conversation.append(message)
        elif message["direction"] == "received":
            is_broadcast = target == 0 and message["target_id"] == 0
            is_direct_to_this_client = (
                target != 0
                and message["sender_id"] == target
                and message["target_id"] == state["client_id"]
            )
            if is_broadcast or is_direct_to_this_client:
                conversation.append(message)
    if not conversation:
        empty = "No broadcast messages yet." if target == 0 else f"No messages with Client #{target} yet."
        st.markdown(f'<div class="empty-chat">{empty}<br><br>Messages are encrypted locally before they reach the relay.</div>', unsafe_allow_html=True)
    for message in conversation:
        outgoing = message["direction"] == "sent"
        direction = "outgoing" if outgoing else "incoming"
        broadcast = " broadcast" if message["target_id"] == 0 else ""
        label = "You" if outgoing else f"Client #{message['sender_id']}"
        timestamp = time.strftime("%H:%M", time.localtime(message["when"]))
        safe_text = html.escape(message["text"]).replace("\n", "<br>")
        st.markdown(
            f'<div class="message-row {direction}"><div class="message-bubble {direction}{broadcast}">'
            f'{safe_text}<div class="message-meta">{label} · {timestamp} · ✓ encrypted</div>'
            f'</div></div>',
            unsafe_allow_html=True,
        )

    if not state["connected"]:
        st.info("Connect to the relay from Connection settings to send messages.")
    elif state["client_id"] is None:
        st.info("Waiting for the relay to assign this browser session a client ID.")
    else:
        text = st.chat_input(f"Message {chat_name}")
        if text:
            try:
                relay.send_message(target, text)
                relay.drain_events()
                st.rerun(scope="fragment")
            except (ValueError, RuntimeError, ConnectionError, OSError) as exc:
                st.error(str(exc))
    total_bytes = fmt_bytes(state["bytes_sent"] + state["bytes_received"])
    st.markdown(f'<div class="session-note">Live updates every 2 seconds · this browser session: {state["sent"]} sent · {state["received"]} received · {total_bytes} encrypted frame traffic · uptime {uptime(state["connected_at"])}</div>', unsafe_allow_html=True)


def main() -> None:
    st.set_page_config(page_title="Relay Chat", page_icon="💬", layout="wide")
    style()
    relay = connection()
    relay.drain_events()
    state = relay.snapshot()
    if "active_target" not in st.session_state:
        st.session_state.active_target = 0
    with st.sidebar:
        st.markdown('<div class="chat-title">Relay Chat</div><div class="chat-subtitle">Encrypted, blind-relay messaging</div>', unsafe_allow_html=True)
        st.divider()
        if state["connected"]:
            st.success(f"Connected · You are #{state['client_id'] if state['client_id'] is not None else '…'}")
        else:
            st.warning("Relay disconnected")
        if st.button("↻  Refresh messages", use_container_width=True):
            relay.drain_events()
            st.rerun()
        st.caption("Incoming messages update automatically every 2 seconds.")
        st.subheader("Chats")
        if st.button("📣  Broadcast", use_container_width=True, type="primary" if st.session_state.active_target == 0 else "secondary"):
            st.session_state.active_target = 0
            st.rerun()
        st.markdown(f'<div class="conversation-preview">{html.escape(conversation_preview(relay.messages, 0, state["client_id"]))}</div>', unsafe_allow_html=True)
        for peer in state["peers"]:
            if st.button(f"👤  Client #{peer}", key=f"peer-{peer}", use_container_width=True, type="primary" if st.session_state.active_target == peer else "secondary"):
                st.session_state.active_target = peer
                st.rerun()
            preview = conversation_preview(relay.messages, peer, state["client_id"])
            st.markdown(f'<div class="conversation-preview">{html.escape(preview)}</div>', unsafe_allow_html=True)
        with st.expander("Start a direct chat"):
            new_target = st.number_input("Client ID", min_value=1, max_value=0xFFFFFFFF, value=1, step=1, label_visibility="collapsed")
            if st.button("Open chat", use_container_width=True):
                st.session_state.active_target = int(new_target)
                st.rerun()
        st.divider()
        with st.expander("Connection settings"):
            host = st.text_input("Relay host", value=st.session_state.get("host", DEFAULT_SERVER_HOST))
            port = st.number_input("TCP port", min_value=1, max_value=65535, value=int(st.session_state.get("port", DEFAULT_SERVER_PORT)), step=1)
            key_path = st.text_input("Shared key path", value=st.session_state.get("key_path", str(DEFAULT_KEY_PATH)))
            if st.button("Connect to relay", use_container_width=True):
                try:
                    relay.connect(host.strip(), int(port), load_key(key_path))
                    st.session_state.update(host=host.strip(), port=int(port), key_path=key_path)
                    st.rerun()
                except (OSError, ValueError, ConnectionError) as exc:
                    st.error(f"Could not connect: {exc}")
            if state["connected"] and st.button("Disconnect", use_container_width=True):
                relay.disconnect()
                relay.drain_events()
                st.rerun()
        with st.expander("Security details"):
            st.caption("XChaCha20-Poly1305-IETF · 32-byte key · 24-byte nonce · 16-byte MAC · authenticated routing metadata. The C relay validates sender IDs and strict incoming sequence numbers, and does not decrypt payloads.")

    render_live_chat(relay)


if __name__ == "__main__":
    main()
