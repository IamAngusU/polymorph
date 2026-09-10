from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from polymorph.connectors.base import DeliveryContext
from polymorph.connectors.http_json import HttpEndpoint, HttpJsonConnector
from polymorph.errors import ConnectorWriteError, WriteOutcome
from polymorph.models.schema import SchemaDescriptor


@dataclass(slots=True)
class _EndpointState:
    attempts: int = 0
    committed: dict[str, dict[str, object]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


class _AckLossServer(ThreadingHTTPServer):
    state: _EndpointState


class _AckLossHandler(BaseHTTPRequestHandler):
    server: _AckLossServer
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(size))
        idempotency_key = self.headers.get("idempotency-key")
        assert isinstance(payload, dict)
        assert idempotency_key is not None

        with self.server.state.lock:
            self.server.state.attempts += 1
            attempt = self.server.state.attempts
            self.server.state.committed.setdefault(idempotency_key, payload)

        if attempt == 1:
            # The destination committed, but its acknowledgement disappears on the real TLS socket.
            self.close_connection = True
            with suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return

        body = b"{}"
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _ReusableTlsTransport(httpx.BaseTransport):
    """Keep an injected real transport alive across connector-created client contexts."""

    def __init__(self, certificate: Path) -> None:
        context = ssl.create_default_context(cafile=str(certificate))
        self._transport = httpx.HTTPTransport(verify=context, retries=0)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        return self._transport.handle_request(request)

    def close(self) -> None:
        # HttpJsonConnector owns each short-lived Client, not this injected transport.
        return

    def close_underlying(self) -> None:
        self._transport.close()


def _write_localhost_certificate(root: Path) -> tuple[Path, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Polymorph fault lab")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = root / "localhost-cert.pem"
    private_key_path = root / "localhost-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, private_key_path


def test_real_tls_ack_loss_is_unknown_and_idempotent_retry_does_not_duplicate(
    tmp_path: Path,
) -> None:
    certificate_path, private_key_path = _write_localhost_certificate(tmp_path)
    server = _AckLossServer(("127.0.0.1", 0), _AckLossHandler)
    server.state = _EndpointState()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certificate_path, private_key_path)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    transport = _ReusableTlsTransport(certificate_path)
    connector = HttpJsonConnector(
        HttpEndpoint(
            f"https://127.0.0.1:{server.server_port}",
            "/records",
            idempotency_header="Idempotency-Key",
            idempotency_contract=True,
        ),
        SchemaDescriptor("fault-lab-target", ()),
        timeout=2.0,
        transport=transport,
    )
    context = DeliveryContext(
        transfer_id="transfer-real-tls-fault",
        record_id="record-1",
        record_digest="1" * 64,
        idempotency_key="delivery-record-1",
    )
    record = {"order_reference": "ORD-0001"}

    try:
        with pytest.raises(ConnectorWriteError) as captured:
            connector.write_records([record], context=context)
        assert captured.value.outcome is WriteOutcome.UNKNOWN

        assert connector.write_records([record], context=context) == 1
        assert server.state.attempts == 2
        assert server.state.committed == {context.idempotency_key: record}
    finally:
        transport.close_underlying()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
