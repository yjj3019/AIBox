#!/bin/bash
#set -x

# --- Configuration ---
# [수정] 프록시 서버 설정을 위한 변수 (필요시 주석 해제 후 사용)
# 예: PROXY_SERVER="http://your.proxy.server:8080"
PROXY_SERVER="http://30.30.30.27:8080"

# CVE 상세 정보가 저장/삭제될 디렉토리
CVE_DETAIL_DIR="/data/iso/AIBox/cve"
LOG_DIR="/data/iso/AIBox/log"
LOG_FILE="${LOG_DIR}/custom_collector.log"

# --- Functions for detailed logging ---
# 스크립트의 모든 출력을 로그 파일과 화면에 동시에 기록
exec > >(tee -a "${LOG_FILE}") 2>&1

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - $1"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - $1"
}

show_usage() {
    echo "Usage: $0 [-d] <cve_list_file>"
    echo ""
    echo "  <cve_list_file>      A text file containing a list of CVE IDs, one per line."
    echo ""
    echo "Actions:"
    echo "  (no flag)            Downloads the .json file for each CVE in the list."
    echo "  -d                   Deletes the .json file for each CVE in the list."
    echo ""
    echo "Example (Download):"
    echo "  $0 custom_cve.txt"
    echo ""
    echo "Example (Delete):"
    echo "  $0 -d custom_cve.txt"
}

# --- Main Script Logic ---
log_info "--- Starting Custom CVE Collector script ---"

# 1. Argument Parsing
MODE="download"
CVE_LIST_FILE=""

if [ "$1" == "-d" ]; then
    MODE="delete"
    if [ -z "$2" ]; then
        log_error "Missing file argument for delete mode."
        show_usage
        exit 1
    fi
    CVE_LIST_FILE="$2"
else
    if [ -z "$1" ] || [[ "$1" == -* ]]; then
        log_error "Missing or invalid file argument for download mode."
        show_usage
        exit 1
    fi
    CVE_LIST_FILE="$1"
fi

log_info "Mode: ${MODE}"
log_info "CVE List File: ${CVE_LIST_FILE}"

# 2. Pre-run Checks
log_info "Checking log directory: ${LOG_DIR}"
if [ ! -d "${LOG_DIR}" ]; then
    mkdir -p "${LOG_DIR}"
    log_info "Log directory created."
fi

if [ ! -f "${CVE_LIST_FILE}" ] || [ ! -r "${CVE_LIST_FILE}" ]; then
    log_error "CVE list file '${CVE_LIST_FILE}' does not exist or is not readable."
    exit 1
fi

log_info "Ensuring CVE detail directory exists: ${CVE_DETAIL_DIR}"
mkdir -p "${CVE_DETAIL_DIR}"
if [ ! -w "${CVE_DETAIL_DIR}" ]; then
    log_error "CVE detail directory '${CVE_DETAIL_DIR}' is not writable by user $(whoami)."
    exit 1
fi

# 3. Read CVE IDs from file
mapfile -t CVE_IDS < <(grep -vE '^\s*$|^#' "${CVE_LIST_FILE}")
if [ ${#CVE_IDS[@]} -eq 0 ]; then
    log_error "No valid CVE IDs found in '${CVE_LIST_FILE}'. Please check the file content."
    exit 1
fi

TOTAL_CVES=${#CVE_IDS[@]}
log_info "Found ${TOTAL_CVES} CVEs to process."

CURRENT_NUM=0
SUCCESS_COUNT=0

# 4. Execute based on mode
if [ "${MODE}" == "download" ]; then
    log_info "\n--- Starting CVE detail download ---"
    for CVE_ID in "${CVE_IDS[@]}"; do
        CURRENT_NUM=$((CURRENT_NUM + 1))
        DETAIL_FILE_PATH="${CVE_DETAIL_DIR}/${CVE_ID}.json"

        if [ -f "${DETAIL_FILE_PATH}" ]; then
            log_info "(${CURRENT_NUM}/${TOTAL_CVES}) Skipping ${CVE_ID}: File already exists."
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            continue
        fi

        log_info "(${CURRENT_NUM}/${TOTAL_CVES}) Fetching details for ${CVE_ID}..."
        
        DETAIL_API_URL="https://access.redhat.com/hydra/rest/securitydata/cve/${CVE_ID}.json"
        
        CURL_COMMAND="/usr/bin/curl -s -w \"\n%{http_code}\" -A 'Mozilla/5.0' --connect-timeout 15 --max-time 60"
        if [ -n "${PROXY_SERVER}" ]; then
            CURL_COMMAND="${CURL_COMMAND} --proxy ${PROXY_SERVER}"
        fi
        CURL_COMMAND="${CURL_COMMAND} ${DETAIL_API_URL}"

        HTTP_RESPONSE=$(eval ${CURL_COMMAND})
        HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed '$d')
        HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)

        if [ "${HTTP_CODE}" -eq 200 ] && [ -n "${HTTP_BODY}" ]; then
            echo "${HTTP_BODY}" | /usr/bin/jq '.' > "${DETAIL_FILE_PATH}"
            log_info " -> Successfully saved details to ${DETAIL_FILE_PATH}"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            log_error " -> Failed to fetch details for ${CVE_ID}. HTTP Code: ${HTTP_CODE}. Skipping."
        fi
        sleep 0.2 # API 서버 부하를 줄이기 위한 짧은 대기
    done
    log_info "\nSuccessfully processed ${SUCCESS_COUNT} out of ${TOTAL_CVES} CVEs for download."

elif [ "${MODE}" == "delete" ]; then
    log_info "\n--- Starting CVE detail deletion ---"
    for CVE_ID in "${CVE_IDS[@]}"; do
        CURRENT_NUM=$((CURRENT_NUM + 1))
        FILE_TO_DELETE="${CVE_DETAIL_DIR}/${CVE_ID}.json"

        if [ -f "${FILE_TO_DELETE}" ]; then
            rm -f "${FILE_TO_DELETE}"
            if [ $? -eq 0 ]; then
                log_info "(${CURRENT_NUM}/${TOTAL_CVES}) Deleted: ${FILE_TO_DELETE}"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                log_error "(${CURRENT_NUM}/${TOTAL_CVES}) Failed to delete: ${FILE_TO_DELETE}"
            fi
        else
            log_info "(${CURRENT_NUM}/${TOTAL_CVES}) Skipping ${CVE_ID}: File not found at ${FILE_TO_DELETE}"
        fi
    done
    log_info "\nSuccessfully processed ${SUCCESS_COUNT} out of ${TOTAL_CVES} CVEs for deletion."
fi

log_info "--- Custom CVE Collector script finished. ---"