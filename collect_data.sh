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
CVE_DETAIL_DIR="${OUTPUT_DIR}/cve"
LOG_DIR="/data/iso/AIBox/log"
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
CURL_COMMAND="/usr/bin/curl -s -w \"\n%{http_code}\" -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' -G --connect-timeout 15 --max-time 60"
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

log_info "Successfully fetched and saved ${COUNT} CVEs to ${OUTPUT_FILE}"
log_info "--- Initial CVE list collection finished successfully ---"


# --- [수정] CVE 상세 정보를 개별 파일로 저장하는 로직 ---
log_info "\n--- Starting CVE detail collection based on ${OUTPUT_FILE} ---"

# 1. CVE 상세 정보를 저장할 디렉토리 생성
log_info "Ensuring CVE detail directory exists: ${CVE_DETAIL_DIR}"
mkdir -p "${CVE_DETAIL_DIR}"

# 1. cve_data.json 파일에서 CVE ID 목록 추출
CVE_IDS=$(/usr/bin/jq -r '.[].CVE' "${OUTPUT_FILE}")
if [ -z "${CVE_IDS}" ]; then
    log_error "Could not extract any CVE IDs from ${OUTPUT_FILE}. Stopping detail collection."
    exit 1
fi

TOTAL_CVES=$(echo "${CVE_IDS}" | wc -l)
log_info "Found ${TOTAL_CVES} CVEs to process for detail collection."

CURRENT_CVE_NUM=0
SUCCESS_COUNT=0
for CVE_ID in ${CVE_IDS}; do
    CURRENT_CVE_NUM=$((CURRENT_CVE_NUM + 1))
    log_info "(${CURRENT_CVE_NUM}/${TOTAL_CVES}) Fetching details for ${CVE_ID}..."
    
    DETAIL_API_URL="https://access.redhat.com/hydra/rest/securitydata/cve/${CVE_ID}.json"
    
    DETAIL_CURL_COMMAND="/usr/bin/curl -s -w \"\n%{http_code}\" -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36' --connect-timeout 15 --max-time 60"
    if [ -n "${PROXY_SERVER}" ]; then
        DETAIL_CURL_COMMAND="${DETAIL_CURL_COMMAND} --proxy ${PROXY_SERVER}"
    fi
    DETAIL_CURL_COMMAND="${DETAIL_CURL_COMMAND} ${DETAIL_API_URL}"

    DETAIL_HTTP_RESPONSE=$(eval ${DETAIL_CURL_COMMAND})
    DETAIL_HTTP_BODY=$(echo "$DETAIL_HTTP_RESPONSE" | sed '$d')
    DETAIL_HTTP_CODE=$(echo "$DETAIL_HTTP_RESPONSE" | tail -n1)

    if [ "${DETAIL_HTTP_CODE}" -eq 200 ] && [ -n "${DETAIL_HTTP_BODY}" ]; then
        # 2. 각 CVE 상세 정보를 개별 JSON 파일로 저장
        DETAIL_FILE_PATH="${CVE_DETAIL_DIR}/${CVE_ID}.json"
        echo "${DETAIL_HTTP_BODY}" | /usr/bin/jq '.' > "${DETAIL_FILE_PATH}"
        log_info " -> Successfully saved details to ${DETAIL_FILE_PATH}"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        log_error "Failed to fetch details for ${CVE_ID}. HTTP Code: ${DETAIL_HTTP_CODE}. Skipping."
    fi
    sleep 0.2 # API 서버 부하를 줄이기 위한 짧은 대기
done

log_info "\nSuccessfully saved details for ${SUCCESS_COUNT} out of ${TOTAL_CVES} CVEs into '${CVE_DETAIL_DIR}' directory."
log_info "--- CVE detail collection script finished successfully ---"
