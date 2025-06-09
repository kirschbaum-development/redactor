#!/bin/bash

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

status=0

# --------------------------------------
# Step 1: PINT (Code style checker)
# --------------------------------------
echo "${YELLOW}✨ Running Pint...${RESET}"
./vendor/bin/pint --test
if [[ $? -ne 0 ]]; then
    echo "${RED}✨ ⭕ Pint found code style issues.${RESET}"
    echo "   ${YELLOW}Run './vendor/bin/pint' to fix them, then commit again.${RESET}"
    echo "   ${YELLOW}Or add '[no-verify]' to your commit message to bypass.${RESET}"
    status=1
else
    echo "${GREEN}✨ ✅ Pint passed.${RESET}"
fi

# --------------------------------------
# Step 2: PHPStan (Static analysis)
# --------------------------------------
echo "${YELLOW}🔢 Running PHPStan...${RESET}"
./vendor/bin/phpstan analyse --no-progress --memory-limit=1G
if [[ $? -ne 0 ]]; then
    echo "${RED}🔢 ⭕ PHPStan reported issues.${RESET}"
    status=1
else
    echo "${GREEN}🔢 ✅ PHPStan passed.${RESET}"
fi

# --------------------------------------
# Step 3: Pest (Tests)
# --------------------------------------
echo "${YELLOW}🧪 Running Pest...${RESET}"
./vendor/bin/pest
if [[ $? -ne 0 ]]; then
    echo "${RED}🧪 ⭕ Pest tests failed.${RESET}"
    status=1
else
    echo "${GREEN}🧪 ✅ All tests passed.${RESET}"
fi

exit $status
