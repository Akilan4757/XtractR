#!/bin/bash

set -e
set -o pipefail

# ---------- COLORS ----------
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ---- Enforce Root ----
if [ "$EUID" -ne 0 ]; then
    echo -e "${GREEN} Run XtractR With Root Permission !!${NC}"
    exec sudo "$0" "$@"
fi

echo -e "${CYAN}"
echo "========================================"
echo "     XtractR Forensic Core Pipeline"
echo "========================================"
echo -e "${NC}"

# --- Dependency Check ---
if ! command -v python3 &> /dev/null; then
    echo -e ""
    exit 1
fi

if python3 -c "import pytsk3" 2>/dev/null; then
echo -e "${GREEN}"
    echo -e "[OK] pytsk3 detected (image support enabled)${NC}"
echo -e "${GREEN}"
else
    echo -e "${YELLOW}[WARN] pytsk3 not installed. Image support disabled.${NC}"
fi

echo
read -p "Enter Case ID: " CASE_ID
read -p "Enter Output Directory (example: ./cases): " OUTPUT_BASE
CASE_DIR="$OUTPUT_BASE/$CASE_ID"

read -p "Enter Evidence Source Path (folder or image): " SOURCE_PATH

if [ ! -e "$SOURCE_PATH" ]; then
    echo -e "${RED}[ERROR] Evidence source does not exist.${NC}"
    exit 1
fi

read -p "Enter Investigator Name (mandatory): " INVESTIGATOR_NAME
if [ -z "$INVESTIGATOR_NAME" ]; then
    echo -e "${RED}[ERROR] Investigator name is mandatory.${NC}"
    exit 1
fi

echo
echo "Enter Investigator Passphrase (input hidden):"
read -s PASSPHRASE
echo
echo

# ==============================
# PHASE 1 - CASE INITIALIZATION
# ==============================
echo -e "${BLUE}========== PHASE 1: CASE INITIALIZATION ==========${NC}"
python3 main.py init \
    --case-id "$CASE_ID" \
    --output "$CASE_DIR" \
    --investigator-name "$INVESTIGATOR_NAME" \
    --passphrase "$PASSPHRASE"

# ==============================
# PHASE 2 - EVIDENCE INGESTION
# ==============================
echo -e "${MAGENTA}========== PHASE 2: EVIDENCE INGESTION ==========${NC}"
python3 main.py ingest \
    --source "$SOURCE_PATH" \
    --case "$CASE_DIR" \
    --passphrase "$PASSPHRASE"

# ==============================
# PHASE 3 - BASELINE FREEZE
# ==============================
echo -e "${CYAN}========== PHASE 3: INTEGRITY BASELINE ==========${NC}"
python3 main.py scan \
    --case "$CASE_DIR" \
    --passphrase "$PASSPHRASE"

# ==============================
# PHASE 4 - PLUGIN EXECUTION
# ==============================
echo -e "${YELLOW}========== PHASE 4: ARTIFACT EXTRACTION ==========${NC}"
python3 main.py run-plugins \
    --case "$CASE_DIR" \
    --passphrase "$PASSPHRASE"

# ==============================
# PHASE 5 - INTELLIGENCE LAYER
# ==============================
echo -e "${WHITE}========== PHASE 5: TIMELINE & CORRELATION ==========${NC}"
python3 main.py process \
    --case "$CASE_DIR" \
    --passphrase "$PASSPHRASE"

# ==============================
# PHASE 6 - REPORT GENERATION
# ==============================
echo -e "${GREEN}========== PHASE 6: LEGAL REPORT GENERATION ==========${NC}"
python3 main.py report \
    --case "$CASE_DIR" \
    --passphrase "$PASSPHRASE"

# ==============================
# PHASE 7 - CRYPTO SEAL & EXPORT
# ==============================
echo -e "${RED}========== PHASE 7: EXPORT & CRYPTOGRAPHIC SEAL ==========${NC}"
python3 main.py export \
    --case "$CASE_DIR" \
    --passphrase "$PASSPHRASE"

echo
echo -e "${CYAN}"
echo "========================================"
echo " PIPELINE COMPLETE"
echo " Case Directory: $CASE_DIR"
echo "========================================"
echo -e "${NC}"
