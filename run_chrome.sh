#!/bin/zsh

set -e

PROJECT_DIR="${0:A:h}"
cd "$PROJECT_DIR"

if [[ -x ".venv/bin/python" ]]; then
  PYTHON=".venv/bin/python"
else
  echo "Virtual environment not found. Creating .venv..."
  python3 -m venv .venv
  PYTHON=".venv/bin/python"
  "$PYTHON" -m pip install -r requirements.txt
fi

PORT=8501
URL="http://127.0.0.1:${PORT}"

if curl -fsS "$URL" >/dev/null 2>&1; then
  echo "The project is already running. Opening Google Chrome..."
  open -a "Google Chrome" "$URL"
  exit 0
fi

echo "Starting the project at ${URL}..."
"$PYTHON" -m streamlit run app.py \
  --server.port "$PORT" \
  --server.headless true &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

for attempt in {1..60}; do
  if curl -fsS "$URL" >/dev/null 2>&1; then
    echo "Opening Google Chrome..."
    open -a "Google Chrome" "$URL"
    wait "$SERVER_PID"
    exit $?
  fi

  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "The Streamlit server stopped before the website was ready."
    wait "$SERVER_PID"
    exit $?
  fi

  sleep 0.25
done

echo "The server did not become ready in time."
exit 1
