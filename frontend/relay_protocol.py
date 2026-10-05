import os
import struct
import binascii

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
)


PROTOCOL_VERSION = 1

PROTOCOL_TYPE_CLIENT_ID = 1
PROTOCOL_TYPE_MESSAGE = 2

PROTOCOL_BROADCAST_ID = 0

CRYPTO_KEY_SIZE = 32
CRYPTO_NONCE_SIZE = 24
CRYPTO_MAC_SIZE = 16

PROTOCOL_HEADER_SIZE = 46
PROTOCOL_MAX_PAYLOAD = 4096
PROTOCOL_MAX_FRAME_SIZE = (
    PROTOCOL_HEADER_SIZE
    + PROTOCOL_MAX_PAYLOAD
    + CRYPTO_MAC_SIZE
)


def load_key(filename: str) -> bytes:
    """
    Load the shared key using the same format as
    the C key_manager.

    config/shared.key contains:
        64 hexadecimal characters
        followed by a newline.

    64 hex characters represent 32 raw bytes.
    """

    with open(filename, "r", encoding="ascii") as f:
        hex_key = f.read(64)

    if len(hex_key) != CRYPTO_KEY_SIZE * 2:
        raise ValueError(
            "Invalid key file: expected 64 hexadecimal characters"
        )

    try:
        key = binascii.unhexlify(hex_key)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(
            "Invalid key file: expected hexadecimal data"
        ) from exc

    if len(key) != CRYPTO_KEY_SIZE:
        raise ValueError(
            f"Invalid decoded key length: {len(key)} bytes"
        )

    return key


def generate_nonce() -> bytes:
    return os.urandom(CRYPTO_NONCE_SIZE)


def build_aad(header: bytes) -> bytes:
    if len(header) < PROTOCOL_HEADER_SIZE:
        raise ValueError("Header too short")

    # Same construction as C build_aad():
    #
    # header[0..21] + header[42..45]
    #
    # 22 bytes + 4 bytes = 26 bytes.
    return header[:22] + header[42:46]


def build_client_id_frame(client_id: int) -> bytes:
    header = bytearray(PROTOCOL_HEADER_SIZE)

    header[0] = PROTOCOL_VERSION
    header[1] = PROTOCOL_TYPE_CLIENT_ID

    struct.pack_into(">I", header, 2, 0)
    struct.pack_into(">I", header, 6, client_id)
    struct.pack_into(">Q", header, 10, 0)
    struct.pack_into(">I", header, 18, 0)

    # Nonce remains zero for the control frame.
    header[22:46] = b"\x00" * CRYPTO_NONCE_SIZE

    return bytes(header)


def build_message_frame(
    key: bytes,
    sender_id: int,
    target_id: int,
    sequence: int,
    plaintext: bytes,
) -> bytes:

    if len(key) != CRYPTO_KEY_SIZE:
        raise ValueError("Invalid key length")

    if len(plaintext) > PROTOCOL_MAX_PAYLOAD:
        raise ValueError("Message is too large")

    nonce = generate_nonce()

    ciphertext_length = (
        len(plaintext) + CRYPTO_MAC_SIZE
    )

    header = bytearray(PROTOCOL_HEADER_SIZE)

    header[0] = PROTOCOL_VERSION
    header[1] = PROTOCOL_TYPE_MESSAGE

    struct.pack_into(
        ">I",
        header,
        2,
        sender_id,
    )

    struct.pack_into(
        ">I",
        header,
        6,
        target_id,
    )

    struct.pack_into(
        ">Q",
        header,
        10,
        sequence,
    )

    struct.pack_into(
        ">I",
        header,
        18,
        ciphertext_length,
    )

    header[22:46] = nonce

    aad = build_aad(bytes(header))

    ciphertext = (
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext,
            aad,
            nonce,
            key,
        )
    )

    if len(ciphertext) != ciphertext_length:
        raise ValueError(
            "Ciphertext length mismatch"
        )

    return bytes(header) + ciphertext


def parse_frame(frame: bytes) -> dict:
    if len(frame) < PROTOCOL_HEADER_SIZE:
        raise ValueError("Frame too short")

    version = frame[0]
    frame_type = frame[1]

    if version != PROTOCOL_VERSION:
        raise ValueError("Invalid protocol version")

    sender_id = struct.unpack_from(
        ">I",
        frame,
        2,
    )[0]

    target_id = struct.unpack_from(
        ">I",
        frame,
        6,
    )[0]

    sequence = struct.unpack_from(
        ">Q",
        frame,
        10,
    )[0]

    ciphertext_length = struct.unpack_from(
        ">I",
        frame,
        18,
    )[0]

    nonce = frame[22:46]

    if frame_type == PROTOCOL_TYPE_CLIENT_ID:

        if ciphertext_length != 0:
            raise ValueError(
                "Invalid client ID frame"
            )

        if len(frame) != PROTOCOL_HEADER_SIZE:
            raise ValueError(
                "Invalid client ID frame size"
            )

        return {
            "version": version,
            "type": frame_type,
            "sender_id": sender_id,
            "target_id": target_id,
            "sequence": sequence,
            "ciphertext_length": 0,
            "nonce": nonce,
        }

    if frame_type != PROTOCOL_TYPE_MESSAGE:
        raise ValueError("Unknown frame type")

    if ciphertext_length < CRYPTO_MAC_SIZE:
        raise ValueError(
            "Ciphertext too short"
        )

    if ciphertext_length > (
        PROTOCOL_MAX_PAYLOAD
        + CRYPTO_MAC_SIZE
    ):
        raise ValueError(
            "Ciphertext too large"
        )

    expected_size = (
        PROTOCOL_HEADER_SIZE
        + ciphertext_length
    )

    if len(frame) != expected_size:
        raise ValueError(
            "Frame size does not match header"
        )

    return {
        "version": version,
        "type": frame_type,
        "sender_id": sender_id,
        "target_id": target_id,
        "sequence": sequence,
        "ciphertext_length": ciphertext_length,
        "nonce": nonce,
    }


def decrypt_message(
    key: bytes,
    frame: bytes,
) -> tuple[dict, bytes]:

    info = parse_frame(frame)

    if info["type"] != PROTOCOL_TYPE_MESSAGE:
        raise ValueError(
            "Frame is not a message"
        )

    ciphertext_start = PROTOCOL_HEADER_SIZE

    ciphertext = frame[ciphertext_start:]

    aad = build_aad(
        frame[:PROTOCOL_HEADER_SIZE]
    )

    plaintext = (
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext,
            aad,
            info["nonce"],
            key,
        )
    )

    return info, plaintext
