#!/bin/bash
#set -x

# --- Configuration ---
# API URL and parameters
API_URL="https://access.redhat.com/hydra/rest/securitydata/cve.json"
PER_PAGE=1000
#PER_PAGE=10

# [수정] 프록시 서버 설정을 위한 변수 추가 (필요시 주석 해제 후 사용)
# 예: PROXY_SERVER="http://your.proxy.server:8080"

PROXY_SERVER="http://30.30.30.27:8080"

# [개선] Set an absolute path for the output file and a dedicated log file for this script
OUTPUT_DIR="/data/iso/AIBox"
OUTPUT_FILE="${OUTPUT_DIR}/cve_data.json"
LOG_DIR="/data/iso/AIBox/logs"
# This script will now create its own detailed log
LOG_FILE="${LOG_DIR}/collect_data_detailed.log"

# --- [개선] Functions for detailed logging ---
# Redirect all stdout/stderr to a dedicated log file.
# This makes debugging this specific script easier.
exec > >(tee -a "${LOG_FILE}") 2>&1

log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - INFO - $1"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR - $1"
}

# --- Main Script Logic ---
log_info "--- Starting CVE data collection script ---"

# 1. [개선] Check if directories exist and are writable
log_info "Checking log directory: ${LOG_DIR}"
if [ ! -d "${LOG_DIR}" ]; then
    mkdir -p "${LOG_DIR}"
    log_info "Log directory created."
fi

log_info "Checking output directory: ${OUTPUT_DIR}"
if [ ! -d "${OUTPUT_DIR}" ]; then
    log_error "Output directory does not exist. Please create it."
    exit 1
fi
if [ ! -w "${OUTPUT_DIR}" ]; then
    log_error "Output directory is not writable by user $(whoami)."
    exit 1
fi

# 2. Prepare API call
AFTER_DATE=$(date -d "365 days ago" +%Y-%m-%d)
log_info "Fetching data for CVEs published after: ${AFTER_DATE}"

# 3. [개선] Execute curl and capture response/HTTP code for better error handling
log_info "Executing curl command with a 60-second timeout..."

# [수정] 프록시 설정이 있을 경우 curl 명령어에 추가
CURL_COMMAND="/usr/bin/curl -s -w \"\n%{http_code}\" -G --connect-timeout 15 --max-time 60"
if [ -n "${PROXY_SERVER}" ]; then
    log_info "Using proxy server: ${PROXY_SERVER}"
    CURL_COMMAND="${CURL_COMMAND} --proxy ${PROXY_SERVER}"
fi
CURL_COMMAND="${CURL_COMMAND} --data-urlencode after=${AFTER_DATE} --data-urlencode severity=critical --data-urlencode severity=important --data-urlencode per_page=${PER_PAGE} ${API_URL}"

HTTP_RESPONSE=$(eval ${CURL_COMMAND})
CURL_EXIT_CODE=$?

# [개선] Check curl's exit code first
if [ ${CURL_EXIT_CODE} -ne 0 ]; then
    log_error "curl command failed with exit code ${CURL_EXIT_CODE}."
    if [ ${CURL_EXIT_CODE} -eq 28 ]; then
        log_error "This indicates a timeout. Check network connectivity, firewall rules, or if a proxy is needed."
    fi
    exit 1
fi

# Separate body and HTTP code
HTTP_BODY=$(echo "$HTTP_RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)

log_info "Curl command finished with HTTP status code: ${HTTP_CODE}"

if [ "${HTTP_CODE}" -ne 200 ]; then
    log_error "API request failed with status code ${HTTP_CODE}."
    log_error "Response Body: ${HTTP_BODY}"
    exit 1
fi

if [ -z "${HTTP_BODY}" ]; then
    log_error "API request succeeded (Code 200), but the response body was empty."
    exit 1
fi

# 4. Process with jq and save
log_info "Processing response with jq and saving to: ${OUTPUT_FILE}"
echo "${HTTP_BODY}" | /usr/bin/jq '.' > "${OUTPUT_FILE}"

# 5. [개선] More detailed final check
if [ ! -s "${OUTPUT_FILE}" ]; then
    log_error "File was created but is empty after jq processing."
    exit 1
fi

JSON_TYPE=$(/usr/bin/jq -r 'type' "${OUTPUT_FILE}" 2>/dev/null)
if [ "$?" -ne 0 ]; then
    log_error "jq command failed. The file likely contains invalid JSON."
    log_error "Content of the file:"
    cat "${OUTPUT_FILE}"
    exit 1
fi

if [ "${JSON_TYPE}" == "array" ]; then
    COUNT=$(/usr/bin/jq 'length' "${OUTPUT_FILE}")
    log_info "Successfully fetched and saved ${COUNT} CVEs to ${OUTPUT_FILE}"
else
    log_error "jq processing succeeded, but expected a JSON array and got '${JSON_TYPE}' instead."
    log_error "Content of the file:"
    cat "${OUTPUT_FILE}"
    exit 1
fi

log_info "--- CVE data collection script finished successfully ---"


