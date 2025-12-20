#!/bin/bash
# Gabby Setup Script
# Downloads and installs all dependencies for the Gabby voice AI agent

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GABBY_DIR="$(dirname "$SCRIPT_DIR")"

# Cleanup function for interrupt handling
cleanup() {
    echo ""
    echo "Cleaning up temporary files..."
    rm -f /tmp/vosk-model.zip /tmp/vosk-lib.zip /tmp/piper.tar.gz
    rm -rf /tmp/vosk-lib
    echo "Cleanup complete."
}
trap cleanup EXIT

echo "=== Gabby Setup Script ==="
echo "Working directory: $GABBY_DIR"

# Create directories
mkdir -p "$GABBY_DIR/models"

# ============================================
# Vosk Speech-to-Text Model
# ============================================
VOSK_MODEL="vosk-model-small-en-us-0.15"
VOSK_MODEL_PATH="$GABBY_DIR/models/$VOSK_MODEL"

if [ ! -d "$VOSK_MODEL_PATH" ]; then
    echo ""
    echo "Downloading Vosk model ($VOSK_MODEL)..."
    wget -q --show-progress "https://alphacephei.com/vosk/models/$VOSK_MODEL.zip" -O /tmp/vosk-model.zip
    echo "Extracting Vosk model..."
    unzip -q /tmp/vosk-model.zip -d "$GABBY_DIR/models/"
    rm /tmp/vosk-model.zip
    echo "Vosk model installed to: $VOSK_MODEL_PATH"
else
    echo "Vosk model already installed at: $VOSK_MODEL_PATH"
fi

# ============================================
# Vosk Library
# ============================================
VOSK_LIB_VERSION="0.3.45"

if ! ldconfig -p | grep -q libvosk; then
    echo ""
    echo "Installing Vosk library (v$VOSK_LIB_VERSION)..."

    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        wget -q --show-progress "https://github.com/alphacep/vosk-api/releases/download/v$VOSK_LIB_VERSION/vosk-linux-x86_64-$VOSK_LIB_VERSION.zip" -O /tmp/vosk-lib.zip
    elif [ "$ARCH" = "aarch64" ]; then
        wget -q --show-progress "https://github.com/alphacep/vosk-api/releases/download/v$VOSK_LIB_VERSION/vosk-linux-aarch64-$VOSK_LIB_VERSION.zip" -O /tmp/vosk-lib.zip
    else
        echo "ERROR: Unsupported architecture: $ARCH"
        echo "Please install Vosk library manually from: https://alphacephei.com/vosk/"
        exit 1
    fi

    unzip -q /tmp/vosk-lib.zip -d /tmp/vosk-lib

    echo "Installing to /usr/local/lib (requires sudo)..."
    sudo cp /tmp/vosk-lib/*/libvosk.so /usr/local/lib/
    sudo ldconfig

    rm -rf /tmp/vosk-lib /tmp/vosk-lib.zip
    echo "Vosk library installed."
else
    echo "Vosk library already installed."
fi

# ============================================
# Piper Text-to-Speech
# ============================================
PIPER_VERSION="2023.11.14-2"
PIPER_VOICE="en_US-amy-medium"

# Install Piper binary
if ! command -v piper &> /dev/null && [ ! -f /usr/local/bin/piper ]; then
    echo ""
    echo "Installing Piper TTS (v$PIPER_VERSION)..."

    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        PIPER_ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        PIPER_ARCH="arm64"
    else
        echo "WARNING: Piper may not be available for $ARCH"
        PIPER_ARCH="amd64"
    fi

    wget -q --show-progress "https://github.com/rhasspy/piper/releases/download/$PIPER_VERSION/piper_linux_$PIPER_ARCH.tar.gz" -O /tmp/piper.tar.gz

    echo "Installing Piper binary (requires sudo)..."
    sudo tar -xzf /tmp/piper.tar.gz -C /usr/local/bin/ --strip-components=1 piper/piper
    sudo chmod +x /usr/local/bin/piper

    # Also install the piper_phonemize library
    sudo tar -xzf /tmp/piper.tar.gz -C /usr/local/lib/ --strip-components=1 piper/lib/
    sudo ldconfig

    rm /tmp/piper.tar.gz
    echo "Piper installed to: /usr/local/bin/piper"
else
    echo "Piper TTS already installed."
fi

# Download Piper voice model
PIPER_MODEL_PATH="$GABBY_DIR/models/$PIPER_VOICE.onnx"
if [ ! -f "$PIPER_MODEL_PATH" ]; then
    echo ""
    echo "Downloading Piper voice model ($PIPER_VOICE)..."

    wget -q --show-progress "https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/amy/medium/en_US-amy-medium.onnx" \
        -O "$PIPER_MODEL_PATH"
    wget -q --show-progress "https://huggingface.co/rhasspy/piper-voices/resolve/main/en/en_US/amy/medium/en_US-amy-medium.onnx.json" \
        -O "$GABBY_DIR/models/$PIPER_VOICE.onnx.json"

    echo "Piper voice model installed to: $PIPER_MODEL_PATH"
else
    echo "Piper voice model already installed at: $PIPER_MODEL_PATH"
fi

# ============================================
# Ollama LLM
# ============================================
echo ""
if command -v ollama &> /dev/null; then
    echo "Ollama is installed."

    # Check if Ollama is running
    if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
        echo "Ollama is running."

        # Check if model is available
        if ! curl -s http://localhost:11434/api/tags | grep -q "llama3.2:3b"; then
            echo "Pulling llama3.2:3b model (this may take a while)..."
            ollama pull llama3.2:3b
        else
            echo "llama3.2:3b model is available."
        fi
    else
        echo "WARNING: Ollama is not running!"
        echo "Please start Ollama with: ollama serve"
    fi
else
    echo "WARNING: Ollama is not installed!"
    echo ""
    echo "To install Ollama:"
    echo "  curl -fsSL https://ollama.com/install.sh | sh"
    echo ""
    echo "Then start it with:"
    echo "  ollama serve"
    echo ""
    echo "And pull the model:"
    echo "  ollama pull llama3.2:3b"
fi

# ============================================
# Summary
# ============================================
echo ""
echo "=== Setup Complete ==="
echo ""
echo "Models installed in: $GABBY_DIR/models/"
ls -la "$GABBY_DIR/models/"

echo ""
echo "To run Gabby:"
echo "  1. Make sure Ollama is running: ollama serve"
echo "  2. Build and run: cargo run --release -p gabby"
echo "  3. Call from SIP phone: sip:gabby@<your-ip>:5060"
echo ""
echo "See scripts/linphone_setup.md for softphone configuration."
