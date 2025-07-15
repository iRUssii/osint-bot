#!/bin/bash

# Check for existing bot process
BOT_PID_FILE="bot_pid.txt"

if [ -f "$BOT_PID_FILE" ]; then
  OLD_PID=$(cat "$BOT_PID_FILE")
  if ps -p $OLD_PID > /dev/null; then
    echo "Bot is already running with PID $OLD_PID. Killing process..."
    kill $OLD_PID
    sleep 2
  else
    echo "Stale PID file found. Previous process is not running."
  fi
fi

# Log startup with timestamp
echo "===== OSINT BOT STARTUP $(date) ====="
echo "Starting environment checks..."

# Check for required variables
if [ -z "$TELEGRAM_BOT_TOKEN" ]; then
  echo "ERROR: TELEGRAM_BOT_TOKEN not set! Cannot continue."
  exit 1
fi

echo "TELEGRAM_BOT_TOKEN: [PRESENT]"
echo "GITHUB_API_TOKEN: [$(if [ -n "$GITHUB_API_TOKEN" ]; then echo "PRESENT"; else echo "MISSING"; fi)]"

# Create data directory if needed
mkdir -p data 2>/dev/null || echo "Note: Could not create data directory"

# Start the bot and save PID
echo "Starting main bot process..."
python osint_bot.py &
BOT_PID=$!
echo $BOT_PID > $BOT_PID_FILE
echo "Bot started with PID $BOT_PID"

# Wait for the process to finish (this keeps the container running)
wait $BOT_PID
exit_code=$?

echo "Bot process exited with code: $exit_code"
rm -f $BOT_PID_FILE

exit $exit_code