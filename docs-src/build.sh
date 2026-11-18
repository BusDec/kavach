#!/bin/sh
# Build the Kavach handouts from the HTML sources with headless Brave.
set -e
cd "$(dirname "$0")"
BRAVE="/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
OUT="../docs"
mkdir -p "$OUT"

print_pdf () {
  "$BRAVE" --headless=new --disable-gpu --no-pdf-header-footer \
    --run-all-compositor-stages-before-draw --virtual-time-budget=8000 \
    --print-to-pdf="$OUT/$2" "file://$(pwd)/$1" 2>/dev/null
  echo "built $2"
}

print_pdf board-brief.html "Kavach-Board-Brief-2026.pdf"
print_pdf it-ot-business-case.html "Kavach-IT-OT-Business-Case.pdf"
print_pdf privacy-obligations.html "Kavach-Privacy-Obligations.pdf"
print_pdf incident-response-checklist.html "Kavach-Incident-Response-Checklist.pdf"
