"""HTTP layer tests: request encoding and TLS certificate verification.

The TLS tests serve a real aiohttp application over a self-signed certificate
(``tests/fixtures/selfsigned.*``, valid until 2126) and check that the SDK
refuses it by default, accepts it with ``verify_tls=False``, and accepts it when
``LIVEPEER_GATEWAY_VERIFY_TLS=0`` is set and no argument is given.
"""

from __future__ import annotations

import contextlib
import email.parser
import pathlib
import ssl
from collections.abc import AsyncIterator, Iterator

import pytest
from aiohttp import web

from livepeer_gateway import http
from livepeer_gateway.discovery import discover_runners
from livepeer_gateway.errors import LivepeerGatewayError
from livepeer_gateway.live_runner import call_runner
from livepeer_gateway.multipart import FilePart, MultipartBody, encode_multipart
from livepeer_gateway.remote_signer import RemoteSignerError, get_signer_info

_FIXTURES = pathlib.Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Request encoding
# ---------------------------------------------------------------------------


def _parse_multipart(content_type: str, body: bytes) -> list[email.message.Message]:
    message = email.parser.BytesParser().parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
    )
    assert message.is_multipart()
    return message.get_payload()


class TestRequestParts:
    def test_json_payload_unchanged(self) -> None:
        method, headers, body = http._request_parts(
            "https://runner.example.com/call", payload={"prompt": "hi"}, headers={"Accept": "*/*"}
        )
        assert method == "POST"
        assert headers["Content-Type"] == "application/json"
        assert headers["Accept"] == "*/*"
        assert body == b'{"prompt": "hi"}'

    def test_no_body_is_get_with_json_accept(self) -> None:
        method, headers, body = http._request_parts("https://runner.example.com/discovery")
        assert method == "GET"
        assert headers["Accept"] == "application/json"
        assert body is None

    def test_multipart_body_sets_boundary_and_no_json_accept(self) -> None:
        multipart = MultipartBody(
            fields={"model": "whisper-large-v3"},
            files=[FilePart("file", 'clip "1".wav', b"RIFF\x00\x01wav", "audio/wav")],
        )
        method, headers, body = http._request_parts(
            "https://runner.example.com/v1/audio/transcriptions", multipart=multipart
        )
        assert method == "POST"
        assert headers["Content-Type"] == f"multipart/form-data; boundary={multipart.boundary}"
        assert "Accept" not in headers
        assert body is not None

        parts = _parse_multipart(headers["Content-Type"], body)
        assert [p.get_param("name", header="content-disposition") for p in parts] == ["model", "file"]
        assert parts[0].get_payload(decode=True) == b"whisper-large-v3"
        assert parts[0].get_content_type() == "text/plain"
        assert parts[1].get_filename() == 'clip %221%22.wav'
        assert parts[1].get_content_type() == "audio/wav"
        assert parts[1].get_payload(decode=True) == b"RIFF\x00\x01wav"

    def test_multipart_encoding_is_repeatable(self) -> None:
        multipart = MultipartBody(fields={"a": "1"}, files=[FilePart("f", "x.bin", b"\x00\xff")])
        assert encode_multipart(multipart) == encode_multipart(multipart)
        # A different body gets its own boundary.
        assert MultipartBody().boundary != MultipartBody().boundary

    def test_multipart_wins_over_payload_in_parts(self) -> None:
        multipart = MultipartBody(fields={"a": "1"})
        _, headers, body = http._request_parts(
            "https://runner.example.com/call", payload={"x": 1}, multipart=multipart
        )
        assert headers["Content-Type"].startswith("multipart/form-data; boundary=")
        assert body == encode_multipart(multipart)


# ---------------------------------------------------------------------------
# TLS verification
# ---------------------------------------------------------------------------


class TestVerifyTlsDefault:
    @pytest.mark.parametrize("value", ["0", "false", "no", " FALSE ", "No"])
    def test_env_disables(self, monkeypatch: pytest.MonkeyPatch, value: str) -> None:
        monkeypatch.setenv(http.VERIFY_TLS_ENV, value)
        assert http._verify_tls_from_env() is False

    @pytest.mark.parametrize("value", [None, "", "1", "true", "yes", "off"])
    def test_anything_else_verifies(self, monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
        if value is None:
            monkeypatch.delenv(http.VERIFY_TLS_ENV, raising=False)
        else:
            monkeypatch.setenv(http.VERIFY_TLS_ENV, value)
        assert http._verify_tls_from_env() is True

    def test_argument_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(http, "DEFAULT_VERIFY_TLS", True)
        assert http._resolve_verify_tls(None) is True
        assert http._resolve_verify_tls(False) is False
        assert http._aiohttp_ssl(None) is None
        assert http._aiohttp_ssl(False) is False
        assert http._urllib_ssl_context(None).verify_mode == ssl.CERT_REQUIRED
        assert http._urllib_ssl_context(False).verify_mode == ssl.CERT_NONE

        monkeypatch.setattr(http, "DEFAULT_VERIFY_TLS", False)
        assert http._resolve_verify_tls(None) is False
        assert http._resolve_verify_tls(True) is True
        assert http._aiohttp_ssl(None) is False
        assert http._urllib_ssl_context(None).verify_mode == ssl.CERT_NONE

    def test_tls_kwargs_forward_only_explicit_values(self) -> None:
        assert http._tls_kwargs(None) == {}
        assert http._tls_kwargs(False) == {"verify_tls": False}
        assert http._tls_kwargs(True) == {"verify_tls": True}


@pytest.fixture
def verify_on(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Pin the module default to verify, whatever the developer's shell has."""
    monkeypatch.delenv(http.VERIFY_TLS_ENV, raising=False)
    monkeypatch.setattr(http, "DEFAULT_VERIFY_TLS", True)
    get_signer_info.cache_clear()  # type: ignore[attr-defined]
    yield
    get_signer_info.cache_clear()  # type: ignore[attr-defined]


def _env_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """What a self-signed stack does: set the variable, re-derive the module default."""
    monkeypatch.setenv(http.VERIFY_TLS_ENV, "0")
    monkeypatch.setattr(http, "DEFAULT_VERIFY_TLS", http._verify_tls_from_env())


@contextlib.asynccontextmanager
async def _serve_tls(app: web.Application) -> AsyncIterator[str]:
    """Serve ``app`` over the self-signed certificate on an ephemeral port."""
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(_FIXTURES / "selfsigned.crt", _FIXTURES / "selfsigned.key")
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_ctx)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    try:
        yield f"https://127.0.0.1:{port}"
    finally:
        await runner.cleanup()


def _runner_app(calls: list[str]) -> web.Application:
    async def call(request: web.Request) -> web.Response:
        calls.append(request.path)
        return web.json_response({"text": "hello"})

    async def sse(request: web.Request) -> web.StreamResponse:
        calls.append(request.path)
        resp = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await resp.prepare(request)
        await resp.write(b"data: one\n\n")
        await resp.write_eof()
        return resp

    app = web.Application()
    app.router.add_post("/call", call)
    app.router.add_post("/sse", sse)
    return app


def _signer_app(calls: list[str]) -> web.Application:
    async def sign(request: web.Request) -> web.Response:
        calls.append(request.path)
        return web.json_response({"address": "0xpayer", "signature": "0xsig"})

    async def discover(request: web.Request) -> web.Response:
        calls.append(request.path)
        return web.json_response(
            [
                {
                    "address": "https://orch.example.com",
                    "runners": [
                        {
                            "url": "https://orch.example.com/apps/a/session",
                            "app": "livepeer/app",
                            "gpu": {"name": "H100"},
                        }
                    ],
                }
            ]
        )

    app = web.Application()
    app.router.add_post("/sign-orchestrator-info", sign)
    app.router.add_get("/discover-orchestrators", discover)
    return app


class TestCallRunnerTls:
    async def test_default_rejects_self_signed_certificate(self, verify_on: None) -> None:
        calls: list[str] = []
        async with _serve_tls(_runner_app(calls)) as base:
            with pytest.raises(LivepeerGatewayError, match="certificate") as info:
                await call_runner(f"{base}/call", payload={"x": 1})
        assert calls == []
        assert info.value.payment_sent is False

    async def test_default_rejects_self_signed_certificate_for_streams(self, verify_on: None) -> None:
        calls: list[str] = []
        async with _serve_tls(_runner_app(calls)) as base:
            with pytest.raises(LivepeerGatewayError, match="certificate"):
                await call_runner(f"{base}/sse", payload={"x": 1}, stream=True)
        assert calls == []

    async def test_argument_opts_out(self, verify_on: None) -> None:
        calls: list[str] = []
        async with _serve_tls(_runner_app(calls)) as base:
            result = await call_runner(f"{base}/call", payload={"x": 1}, verify_tls=False)
            async with await call_runner(
                f"{base}/sse", payload={"x": 1}, verify_tls=False, stream=True
            ) as stream:
                lines = [line async for line in stream.aiter_lines() if line]
        assert result.data == {"text": "hello"}
        assert lines == ["data: one"]
        assert calls == ["/call", "/sse"]

    async def test_environment_opts_out(self, verify_on: None, monkeypatch: pytest.MonkeyPatch) -> None:
        _env_opt_out(monkeypatch)
        calls: list[str] = []
        async with _serve_tls(_runner_app(calls)) as base:
            result = await call_runner(f"{base}/call", payload={"x": 1})
        assert result.data == {"text": "hello"}
        assert calls == ["/call"]

    async def test_argument_wins_over_environment(
        self, verify_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _env_opt_out(monkeypatch)
        calls: list[str] = []
        async with _serve_tls(_runner_app(calls)) as base:
            with pytest.raises(LivepeerGatewayError, match="certificate"):
                await call_runner(f"{base}/call", payload={"x": 1}, verify_tls=True)
        assert calls == []


class TestSignerAndDiscoveryTls:
    async def test_signer_default_rejects_self_signed_certificate(self, verify_on: None) -> None:
        calls: list[str] = []
        async with _serve_tls(_signer_app(calls)) as base:
            with pytest.raises(LivepeerGatewayError, match="certificate"):
                await get_signer_info(base)
        assert calls == []

    async def test_signer_honors_argument_and_environment(
        self, verify_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        async with _serve_tls(_signer_app(calls)) as base:
            signer = await get_signer_info(base, None, verify_tls=False)
            assert signer.address == "0xpayer"

            get_signer_info.cache_clear()  # type: ignore[attr-defined]
            _env_opt_out(monkeypatch)
            signer = await get_signer_info(base)
            assert signer.address == "0xpayer"
        assert calls == ["/sign-orchestrator-info", "/sign-orchestrator-info"]

    async def test_discovery_default_rejects_self_signed_certificate(self, verify_on: None) -> None:
        calls: list[str] = []
        async with _serve_tls(_signer_app(calls)) as base:
            with pytest.raises(RemoteSignerError, match="certificate"):
                await discover_runners(signer_url=base)
        assert calls == []

    async def test_discovery_honors_argument_and_environment(
        self, verify_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        async with _serve_tls(_signer_app(calls)) as base:
            entries = await discover_runners(signer_url=base, verify_tls=False)
            assert entries[0]["runners"][0]["app"] == "livepeer/app"

            _env_opt_out(monkeypatch)
            entries = await discover_runners(signer_url=base)
            assert entries[0]["runners"][0]["app"] == "livepeer/app"
        assert calls == ["/discover-orchestrators", "/discover-orchestrators"]

    def test_sync_request_default_rejects_self_signed_certificate(self, verify_on: None) -> None:
        import asyncio

        calls: list[str] = []

        async def scenario() -> str:
            async with _serve_tls(_signer_app(calls)) as base:
                return await asyncio.to_thread(_sync_probe, base)

        assert "certificate" in asyncio.run(scenario())
        assert calls == []


def _sync_probe(base: str) -> str:
    try:
        http.post_json_sync(f"{base}/sign-orchestrator-info", {})
    except LivepeerGatewayError as e:
        return str(e)
    return ""
