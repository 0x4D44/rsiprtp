# Gabby - Voice AI SIP Agent

Talk to an AI over the phone! Gabby is a voice AI application that accepts SIP phone calls and enables natural conversation using:

- **Vosk** - Fast, offline speech-to-text
- **Ollama** - Local LLM inference (llama3.2)
- **Piper** - Low-latency neural text-to-speech

## Features

- Accept incoming SIP calls from any softphone
- Real-time speech recognition
- Natural conversational AI responses
- Neural voice synthesis
- Fully local - no cloud services required
- Low latency audio pipeline

## Requirements

- Rust 1.70+
- ~2GB disk space for models
- 4GB+ RAM recommended
- Linux (x86_64 or aarch64)

## Quick Start

### 1. Install Dependencies

**Option A: Use the setup script (recommended)**

```bash
cd crates/gabby
./scripts/setup.sh
```

This downloads and installs:
- Vosk speech recognition model (~50MB)
- Vosk library (libvosk)
- Piper TTS binary and voice model (~100MB)
- Checks for Ollama and the llama3.2:3b model

**Option B: Manual installation**

Install libvosk (required for speech recognition):

```bash
# Download Vosk library (v0.3.45 - latest with prebuilt binaries)
wget "https://github.com/alphacep/vosk-api/releases/download/v0.3.45/vosk-linux-x86_64-0.3.45.zip" -O /tmp/vosk-lib.zip

# For aarch64/arm64, use instead:
# wget "https://github.com/alphacep/vosk-api/releases/download/v0.3.45/vosk-linux-aarch64-0.3.45.zip" -O /tmp/vosk-lib.zip

# Extract and install
unzip /tmp/vosk-lib.zip -d /tmp/vosk-lib
sudo cp /tmp/vosk-lib/vosk-linux-x86_64-0.3.45/libvosk.so /usr/local/lib/
sudo ldconfig

# Verify installation
ldconfig -p | grep vosk
```

Download the Vosk model:

```bash
cd crates/gabby
mkdir -p models
wget "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip" -O /tmp/vosk-model.zip
unzip /tmp/vosk-model.zip -d models/
```

### 2. Start Ollama

In a separate terminal:
```bash
ollama serve
```

If you haven't pulled the model yet:
```bash
ollama pull llama3.2:3b
```

### 3. Run Gabby

```bash
cargo run --release -p gabby
```

You should see:
```
Starting Gabby voice AI agent
Loading Vosk model...
Vosk model loaded successfully
SIP server listening on 0.0.0.0:5060
Gabby is ready to receive calls!
Call sip:gabby@<your-ip>:5060 from your SIP phone
```

### 4. Make a Call

Using Linphone or another SIP client, call:
```
sip:gabby@<your-ip>:5060
```

See [scripts/linphone_setup.md](scripts/linphone_setup.md) for detailed softphone configuration.

## Configuration

Copy the example config and customize:

```bash
cp gabby.example.toml gabby.toml
```

### Configuration Options

```toml
[server]
sip_host = "0.0.0.0"      # Listen address
sip_port = 5060           # SIP port
rtp_port_start = 10000    # RTP port range start

[stt]
model_path = "./models/vosk-model-small-en-us-0.15"

[llm]
endpoint = "http://localhost:11434"
model = "llama3.2:3b"
system_prompt = """
You are Gabby, a friendly voice assistant.
Keep responses concise for spoken conversation.
"""
temperature = 0.7
max_tokens = 150

[tts]
piper_binary = "/usr/local/bin/piper"
model_path = "./models/en_US-amy-medium.onnx"

[vad]
silence_threshold = 0.02
silence_duration_ms = 700   # Silence needed to end turn
```

### CLI Options

```
gabby [OPTIONS]

Options:
  -c, --config <FILE>     Config file path [default: gabby.toml]
  -p, --port <PORT>       SIP port (overrides config)
  -l, --log-level <LEVEL> Log level [default: info]
  -h, --help              Print help
  -V, --version           Print version
```

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │           GABBY SERVER                  │
                    │                                         │
  SIP Phone ───────▶│  SIP ──▶ RTP ──▶ Decode ──▶ Resample   │
       ▲            │                      │           │      │
       │            │                      ▼           ▼      │
       │            │                 G.711 PCM    8k→16k    │
       │            │                      │           │      │
       │            │                      ▼           ▼      │
       │            │                    Vosk STT ◀──────────│
       │            │                      │                  │
       │            │                (transcript)             │
       │            │                      │                  │
       │            │                      ▼                  │
       │            │                 Ollama LLM              │
       │            │                      │                  │
       │            │                 (response)              │
       │            │                      │                  │
       │            │                      ▼                  │
       │            │                 Piper TTS               │
       │            │                      │                  │
       │            │                 22k→8k                  │
       │            │                      │                  │
       └────────────│──────── RTP ◀── Encode ◀─────────────│
                    │                                         │
                    └─────────────────────────────────────────┘
```

## Voice Activity Detection

Gabby uses a hybrid VAD approach:
1. **Energy-based**: Detects silence using RMS audio level
2. **STT-based**: Monitors partial transcription stability
3. **Timing**: 700ms of silence after speech triggers response

## Troubleshooting

### "Failed to load Vosk model"
- Run `./scripts/setup.sh` to download the model
- Check the model path in config matches actual location

### "TTS unavailable"
- Piper may not be installed
- Run setup.sh or install manually from https://github.com/rhasspy/piper

### "Connection refused" from Ollama
- Start Ollama: `ollama serve`
- Pull the model: `ollama pull llama3.2:3b`

### No audio from caller
- Enable only G.711 (PCMU/PCMA) codecs in your softphone
- Disable Opus and other codecs

### Call doesn't connect
- Check firewall allows UDP 5060 and 10000-20000
- Verify Gabby is running and shows "ready to receive calls"

## Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 5060 | UDP | SIP signaling |
| 10000-20000 | UDP | RTP audio streams |

## License

MIT

## Credits

- [Vosk](https://alphacephei.com/vosk/) - Speech recognition
- [Ollama](https://ollama.ai/) - Local LLM inference
- [Piper](https://github.com/rhasspy/piper) - Text-to-speech
- mdsiprtp - SIP/RTP stack (included in this workspace)
