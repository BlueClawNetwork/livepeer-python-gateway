# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Behavior change

- **TLS certificates are verified by default.** Every HTTP call the SDK makes
  (runner calls, signer, discovery, payments, BYOC) now checks the server
  certificate against the system trust store. A caller that reaches a
  self-signed orchestrator or signer without any TLS setting will fail with a
  `LivepeerGatewayError` whose message contains `certificate`. Opt out for a
  self-signed local stack with one line in the environment:

  ```sh
  export LIVEPEER_GATEWAY_VERIFY_TLS=0
  ```

  or per call with `verify_tls=False` on `call_runner`, `discover_runners`,
  `discover_orchestrator_runners`, `get_signer_info`, `LivePaymentSession`, and
  `submit_byoc_job`. The per-call argument overrides the environment.

### Added

- `call_runner(multipart=MultipartBody(...))` sends a `multipart/form-data`
  body, for OpenAI-style audio endpoints such as `/v1/audio/transcriptions`.
  `MultipartBody` and `FilePart` are exported from `livepeer_gateway`. The body
  is held in memory and re-sent byte for byte after a 402 payment challenge;
  `payload` and `multipart` are mutually exclusive, and multipart is limited to
  `POST` and `PUT`.
- `verify_tls` keyword argument and `livepeer_gateway.http.DEFAULT_VERIFY_TLS`
  (initialized from `LIVEPEER_GATEWAY_VERIFY_TLS`), see above.
- `LiveRunnerCallStream.session_id` carries the payment challenge's
  `manifest_id` for `call_runner(..., stream=True)`, as
  `LiveRunnerCallResult.session_id` already did for unary calls. It is `""`
  when no challenge was answered.
- `LivepeerGatewayError.payment_sent` (so every SDK error has it) is `True` when
  `call_runner` raises from an attempt whose request already carried
  `Livepeer-Payment` headers. A gateway may fail over to another runner only
  while it is `False`.

## [1.0.0] - 2026-08-11

The first stable release of the Livepeer Python SDK.

### Added

- Live Runner registration, discovery, session reservation, raw calls, proxy
  calls, and session lifecycle events.
- Scope startup for application and serverless runners.
- BYOC inference and training jobs, including signed payments, payment refresh,
  status polling, and completion waits.
- Live video-to-video jobs with capability-aware orchestrator discovery,
  ordered fallback selection, token-based configuration, and remote-signer
  payments.
- Multi-track media publishing and media output APIs for bytes, decoded frames,
  and demuxed packets.
- Trickle channels for control messages, events, JSON Lines, keepalives, and
  observable publisher/subscriber statistics.
- Orchestrator information, capability discovery, TLS trust-on-first-use, and
  typed SDK errors.

### Changed

- Declared the generated gRPC client's actual minimum runtime versions:
  `grpcio>=1.76.0` and `protobuf>=6.31.1`.
- Completed the package metadata and documented installation from PyPI.

[Unreleased]: https://github.com/livepeer/livepeer-python-gateway/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/livepeer/livepeer-python-gateway/releases/tag/v1.0.0
