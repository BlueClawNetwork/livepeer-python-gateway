from __future__ import annotations

import json
import os
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import ParseResult, urlparse
from urllib.request import Request, urlopen

import aiohttp

from .errors import (
    LivepeerHTTPError,
    LivepeerGatewayError,
    SignerRefreshRequired,
    SkipPaymentCycle,
)
from .multipart import MultipartBody, encode_multipart

_REFRESH_SESSION_ORCHESTRATOR_URL_HEADER = "Livepeer-Orchestrator-URL"

VERIFY_TLS_ENV = "LIVEPEER_GATEWAY_VERIFY_TLS"
_FALSE_VALUES = frozenset({"0", "false", "no"})


def _verify_tls_from_env() -> bool:
    """Read ``LIVEPEER_GATEWAY_VERIFY_TLS``: ``0``, ``false`` or ``no`` disable verification."""
    return os.environ.get(VERIFY_TLS_ENV, "").strip().lower() not in _FALSE_VALUES


# Process-wide default for TLS certificate verification. Every HTTP call the SDK
# makes verifies certificates against the system trust store unless this is False
# or the call passes ``verify_tls=False``. Self-signed local stacks set
# ``LIVEPEER_GATEWAY_VERIFY_TLS=0`` in their environment.
DEFAULT_VERIFY_TLS: bool = _verify_tls_from_env()


def _resolve_verify_tls(verify_tls: bool | None) -> bool:
    """A per-call ``verify_tls`` argument overrides the module default; None means default."""
    return DEFAULT_VERIFY_TLS if verify_tls is None else bool(verify_tls)


def _tls_kwargs(verify_tls: bool | None) -> dict[str, bool]:
    """Forward an explicit ``verify_tls`` argument, and nothing when the default applies."""
    return {} if verify_tls is None else {"verify_tls": verify_tls}


def _aiohttp_ssl(verify_tls: bool | None) -> None | bool:
    """``ssl=`` value for ``aiohttp.TCPConnector``: None (aiohttp default, system trust store) or False."""
    return None if _resolve_verify_tls(verify_tls) else False


def _urllib_ssl_context(verify_tls: bool | None) -> ssl.SSLContext:
    """``context=`` for ``urllib.request.urlopen``: the default verifying context, or an unverified one."""
    if _resolve_verify_tls(verify_tls):
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def _truncate(s: str, max_len: int = 2000) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + f"...(+{len(s) - max_len} chars)"


def _http_error_body(e: HTTPError) -> str:
    """
    Best-effort read of an HTTPError response body for debugging.
    """
    try:
        b = e.read()
        if not b:
            return ""
        if isinstance(b, bytes):
            return b.decode("utf-8", errors="replace")
        return str(b)
    except Exception:
        return ""


def _extract_error_message_from_body(body: str) -> str:
    """
    Best-effort extraction of a useful error message from an HTTP error body.

    If the body is JSON and matches {"error": {"message": "..."}}, return that message.
    Otherwise return the full body.

    Always truncates the returned value for readability.
    """
    s = body.strip()
    if not s:
        return ""

    try:
        data = json.loads(s)
    except Exception:
        return _truncate(body)

    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict):
            msg = err.get("message")
            if isinstance(msg, str) and msg:
                return _truncate(msg)

    return _truncate(body)


def _extract_error_message(e: HTTPError) -> str:
    """
    Best-effort extraction of a useful error message from an HTTPError body.
    """
    return _extract_error_message_from_body(_http_error_body(e))


def _header_value(headers: dict[str, str], name: str) -> str | None:
    needle = name.lower()
    for key, value in headers.items():
        if key.lower() == needle and isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _request_parts(
    url: str,
    *,
    method: str | None = None,
    payload: dict[str, Any] | None = None,
    multipart: MultipartBody | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[str, dict[str, str], bytes | None]:
    """Resolve ``(method, headers, body)`` for a request.

    ``payload`` is JSON-encoded with ``Content-Type: application/json`` and
    ``Accept: application/json``. ``multipart`` is encoded as
    ``multipart/form-data`` (the boundary is fixed per ``MultipartBody``, so a
    retry sends byte-identical bytes) and sets no ``Accept``; the app picks the
    response format. ``headers`` override anything set here.
    """
    req_headers: dict[str, str] = {"User-Agent": "livepeer-python-gateway/0.1"}
    body: bytes | None = None
    if multipart is not None:
        req_headers["Content-Type"] = multipart.content_type
        body = encode_multipart(multipart)
    else:
        req_headers["Accept"] = "application/json"
        if payload is not None:
            req_headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
    if headers:
        req_headers.update(headers)

    resolved_method = method.upper() if method else ("POST" if body is not None else "GET")
    return resolved_method, req_headers, body


# Name kept for callers that imported the JSON-only helper.
_json_request_parts = _request_parts


def _raise_http_json_error(
    status: int,
    url: str,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> None:
    message = _extract_error_message_from_body(body)
    body_part = f"; body={message!r}" if message else ""
    if status == 480:
        raise SignerRefreshRequired(
            f"Signer returned HTTP 480 (refresh session required) (url={url}){body_part}",
            orchestrator_url=_header_value(headers or {}, _REFRESH_SESSION_ORCHESTRATOR_URL_HEADER),
        )
    if status == 482:
        raise SkipPaymentCycle(
            f"Signer returned HTTP 482 (skip payment cycle) (url={url}){body_part}"
        )
    raise LivepeerHTTPError(
        status,
        url,
        body,
        f"HTTP {status} from endpoint (url={url}){body_part}",
    )


def _ensure_json_object(data: Any, *, url: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise LivepeerGatewayError(
            f"HTTP JSON error: expected JSON object, got {type(data).__name__} (url={url})"
        )
    return data


def request_json_sync(
    url: str,
    *,
    method: str | None = None,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> Any:
    """
    Make a JSON HTTP request and parse the JSON response.

    If method is None, defaults to POST when payload is provided, otherwise GET.
    ``verify_tls`` overrides ``DEFAULT_VERIFY_TLS`` for this call.

    Raises LivepeerGatewayError on HTTP/network/JSON parsing errors.
    """
    resolved_method, req_headers, body = _request_parts(
        url,
        method=method,
        payload=payload,
        headers=headers,
    )
    req = Request(url, data=body, headers=req_headers, method=resolved_method)
    ssl_ctx = _urllib_ssl_context(verify_tls)

    try:
        with urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            raw = resp.read().decode("utf-8")
        data: Any = json.loads(raw)
    except HTTPError as e:
        raw_body = _http_error_body(e)
        body_text = _extract_error_message_from_body(raw_body)
        body_part = f"; body={body_text!r}" if body_text else ""
        if e.code == 480:
            raise SignerRefreshRequired(
                f"Signer returned HTTP 480 (refresh session required) (url={url}){body_part}",
                orchestrator_url=_header_value(
                    dict(e.headers.items()),
                    _REFRESH_SESSION_ORCHESTRATOR_URL_HEADER,
                ),
            ) from e
        if e.code == 482:
            raise SkipPaymentCycle(
                f"Signer returned HTTP 482 (skip payment cycle) (url={url}){body_part}"
            ) from e
        raise LivepeerHTTPError(
            e.code,
            url,
            raw_body,
            f"HTTP {e.code} from endpoint (url={url}){body_part}",
        ) from e
    except ConnectionRefusedError as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: connection refused (is the server running? is the host/port correct?) (url={url})"
        ) from e
    except URLError as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: failed to reach endpoint: {getattr(e, 'reason', e)} (url={url})"
        ) from e
    except json.JSONDecodeError as e:
        raise LivepeerGatewayError(f"HTTP JSON error: endpoint did not return valid JSON: {e} (url={url})") from e
    except Exception as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: unexpected error: {e.__class__.__name__}: {e} (url={url})"
        ) from e

    return data


def post_json_sync(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> dict[str, Any]:
    """
    POST JSON to `url` and parse a JSON object response.
    """
    data = request_json_sync(
        url,
        payload=payload,
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    return _ensure_json_object(data, url=url)


def get_json_sync(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> Any:
    """
    GET JSON from `url` and parse the response.
    """
    return request_json_sync(url, headers=headers, timeout=timeout, verify_tls=verify_tls)


async def _request_body(
    url: str,
    *,
    method: str | None = None,
    payload: dict[str, Any] | None = None,
    multipart: MultipartBody | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> tuple[bytes, str]:
    """
    Make an async HTTP request (JSON ``payload`` or ``multipart`` body) and return
    the raw response body.

    Returns ``(body, content_type)`` without assuming the response is JSON;
    request semantics and error mapping match request_json.

    If method is None, defaults to POST when a body is provided, otherwise GET.
    ``verify_tls`` overrides ``DEFAULT_VERIFY_TLS`` for this call.

    Raises LivepeerGatewayError on HTTP/network errors.
    """
    resolved_method, req_headers, body = _request_parts(
        url,
        method=method,
        payload=payload,
        multipart=multipart,
        headers=headers,
    )

    try:
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        connector = aiohttp.TCPConnector(ssl=_aiohttp_ssl(verify_tls))
        async with aiohttp.ClientSession(timeout=client_timeout, connector=connector) as session:
            async with session.request(resolved_method, url, data=body, headers=req_headers) as resp:
                raw = await resp.read()
                content_type = resp.content_type or ""
                if resp.status >= 400:
                    _raise_http_json_error(
                        resp.status, url, raw.decode(errors="replace"), dict(resp.headers.items())
                    )
    except (SignerRefreshRequired, SkipPaymentCycle, LivepeerGatewayError):
        raise
    except ConnectionRefusedError as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: connection refused (is the server running? is the host/port correct?) (url={url})"
        ) from e
    except getattr(aiohttp, "ClientConnectorError", ()) as e:
        os_error = getattr(e, "os_error", None)
        if isinstance(os_error, ConnectionRefusedError):
            raise LivepeerGatewayError(
                f"HTTP JSON error: connection refused (is the server running? is the host/port correct?) (url={url})"
            ) from e
        raise LivepeerGatewayError(
            f"HTTP JSON error: failed to reach endpoint: {getattr(e, 'message', e)} (url={url})"
        ) from e
    except (TimeoutError, aiohttp.ClientError) as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: failed to reach endpoint: {getattr(e, 'message', e)} (url={url})"
        ) from e
    except Exception as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: unexpected error: {e.__class__.__name__}: {e} (url={url})"
        ) from e

    return raw, content_type


async def request_json(
    url: str,
    *,
    method: str | None = None,
    payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> Any:
    """
    Make an async JSON HTTP request and parse the JSON response.

    If method is None, defaults to POST when payload is provided, otherwise GET.
    ``verify_tls`` overrides ``DEFAULT_VERIFY_TLS`` for this call.

    Raises LivepeerGatewayError on HTTP/network/JSON parsing errors.
    """
    raw, _ = await _request_body(
        url,
        method=method,
        payload=payload,
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise LivepeerGatewayError(
            f"HTTP JSON error: endpoint did not return valid JSON: {e} (url={url})"
        ) from e


async def open_stream(
    url: str,
    *,
    method: str | None = None,
    payload: dict[str, Any] | None = None,
    multipart: MultipartBody | None = None,
    headers: dict[str, str] | None = None,
    connect_timeout: float = 10.0,
    verify_tls: bool | None = None,
) -> tuple[aiohttp.ClientSession, aiohttp.ClientResponse]:
    """
    Open an HTTP request and return the live (session, response) without reading the
    body, for streaming responses (SSE, chunked). The caller owns both and must close
    them.

    No total timeout (streams run indefinitely) only connect/first-byte are bounded.
    ``verify_tls`` overrides ``DEFAULT_VERIFY_TLS`` for this call.
    Raises LivepeerHTTPError on >= 400 (e.g. the 402 payment retry).
    """
    resolved_method, req_headers, body = _request_parts(
        url,
        method=method,
        payload=payload,
        multipart=multipart,
        headers=headers,
    )

    timeout = aiohttp.ClientTimeout(total=None, sock_connect=connect_timeout, sock_read=None)
    session = aiohttp.ClientSession(
        timeout=timeout, connector=aiohttp.TCPConnector(ssl=_aiohttp_ssl(verify_tls))
    )
    try:
        resp = await session.request(resolved_method, url, data=body, headers=req_headers)
    except (TimeoutError, aiohttp.ClientError) as e:
        await session.close()
        raise LivepeerGatewayError(
            f"HTTP stream error: failed to reach endpoint: {getattr(e, 'message', e)} (url={url})"
        ) from e
    if resp.status >= 400:
        raw = await resp.text()
        resp.release()
        await session.close()
        _raise_http_json_error(resp.status, url, raw, dict(resp.headers.items()))
    return session, resp


async def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> dict[str, Any]:
    """
    POST JSON to `url` and parse a JSON object response.
    """
    data = await request_json(
        url,
        payload=payload,
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    return _ensure_json_object(data, url=url)


async def get_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> Any:
    """
    GET JSON from `url` and parse the response.
    """
    return await request_json(url, headers=headers, timeout=timeout, verify_tls=verify_tls)


async def _post_empty(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    verify_tls: bool | None = None,
) -> None:
    """POST an empty body to ``url`` and discard the response."""
    await _request_body(
        url,
        method="POST",
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
    )


def _parse_http_url(url: str, *, context: str = "URL") -> ParseResult:
    """
    Normalize a URL for HTTP(S) endpoints.

    Accepts:
    - "host:port" (implicitly https://host:port)
    - "http://host:port[/...]"
    - "https://host:port[/...]"
    """
    url = url.strip()
    normalized = url if "://" in url else f"https://{url}"
    parsed = urlparse(normalized)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http:// or https:// {context}s are supported (got {parsed.scheme!r})")
    if not parsed.netloc:
        raise ValueError(f"Invalid {context}: {url!r}")
    return parsed


def _http_origin(url: str) -> str:
    """
    Normalize a URL (possibly with a path) into a scheme:// origin (scheme + host:port).

    Accepts:
    - "host:port" (implicitly https://host:port)
    - "http://host:port[/...]" (path/query/fragment are ignored)
    - "https://host:port[/...]" (path/query/fragment are ignored)
    """
    parsed = _parse_http_url(url)
    return f"{parsed.scheme}://{parsed.netloc}"
