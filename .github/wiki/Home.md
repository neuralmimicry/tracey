# Tracey — Wiki Home

**Tracey** is an asynchronous swarm runtime for anomaly assessment, security posture governance, and fleet telemetry. It combines event ingestion, adaptive fuzzy scoring, multi-agent consensus, elected coordination, bounded JSONL audit storage, and optional binary update lifecycles.

> ☕ [Support NeuralMimicry on Crowdfunder](https://www.crowdfunder.co.uk/p/qr/aWggxwPW?utm_campaign=sharemodal&utm_medium=referral&utm_source=shortlink)

---

## Quick navigation

| Page | Description |
|---|---|
| [Getting Started](Getting-Started) | Build and run Tracey locally |
| [Configuration Reference](Configuration-Reference) | All config keys, defaults, and env overrides |
| [Default-On Subsystems](Default-On-Subsystems) | What runs automatically and what requires explicit opt-in |
| [TUI Dashboard](TUI-Dashboard) | Three-page operator dashboard (`--tui`) |
| [TraceyBan & TraceyGuard](TraceyBan-and-TraceyGuard) | Jail-based banning and GPU security monitoring |
| [Deployment](Deployment) | systemd service, Debian packages, loader binary |
| [Security Model](Security-Model) | Auth modes, shared-key MAC, hardening guidance |
| [Contributing](Contributing) | Running the preflight suite, PR guidelines |

---

## Quick start

```bash
# Run the main runtime
cargo run --bin tracey

# Run with the operator TUI dashboard
cargo run --bin tracey -- --tui

# Run under the supervisor (crash-restart + zero-downtime update)
cargo run --bin tracey -- --supervisor

# Local verification (200+ tests)
bash scripts/preflight.sh
bash scripts/preflight.sh --ci
```

## Default-on subsystems

| Subsystem | Default | Notes |
|---|---|---|
| Synthetic sensors | **On** | Four streams: system_cpu, network_flow, user_actions, automation |
| Embedded Linux collectors | **On** | CPU, memory, disk, network, process, GPU metrics |
| TraceyGuard | **On** | GPU identity discovery; synthetic fallback when no devices found |
| Discovery gossip | **On** | UDP 47990, shared-key MAC |
| Status API | **On** | `0.0.0.0:48000` — enable token or OIDC auth before public exposure |
| TraceyBan | **Off** | Jail logic and cross-agent ban intelligence — opt-in |
| Tracey OIDC auth | **Off** | Enable with `auth.mode = token` or `oidc` |

## Key interfaces

| Surface | Bind | Purpose |
|---|---|---|
| Status API | `0.0.0.0:48000` | `/status`, `/health`, TraceyBan/Guard control, `/metrics` |
| Discovery | `0.0.0.0:47990` UDP | Peer presence gossip |
| Loader transfer | `0.0.0.0:47988` HTTP | Binary distribution to fleet peers |

## Get involved

- 🐛 [Report a bug or request a feature](https://github.com/neuralmimicry/tracey/issues)
- 💬 [Join the discussion](https://github.com/neuralmimicry/tracey/discussions)
- 📧 Direct support: [info@neuralmimicry.ai](mailto:info@neuralmimicry.ai) · **£1,000/day + VAT**
- 🌐 [neuralmimicry.ai](https://neuralmimicry.ai)
