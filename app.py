import argparse
import getpass
import sys
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import logging

# --- 로깅 설정 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__, template_folder='.', static_folder='.')
CORS(app)

CONFIG = {}
PROMPTS = {} # 프롬프트 내용을 서버에서도 관리

def initialize_prompts():
    """초기 프롬프트를 설정합니다."""
    PROMPTS.update({
        "시스템 문제 해결 전문가 프롬프트": """당신은 20년 경력의 Red Hat Certified Architect (RHCA)이자 Linux Foundation의 Technical Advisory Board 멤버입니다. 

**전문성 컨텍스트:**
- Red Hat Enterprise Linux 모든 버전에 대한 깊은 이해
- 대규모 엔터프라이즈 환경에서의 실전 경험
- 커널 레벨부터 애플리케이션 레벨까지의 종합적 지식
- 최신 기술 트렌드와 베스트 프랙티스에 대한 지식

**답변 요구사항:**
1. 근본 원인 분석 (5 Why 기법 적용)
2. 단계별 해결 방법 (우선순위별)
3. 실행 가능한 명령어와 스크립트
4. 예방 조치 및 모니터링 방안
5. 비즈니스 영향도 고려
6. 관련 Red Hat KB 문서나 최신 정보가 필요한 경우 "Web Search 필요"라고 명시

**질문:** [구체적인 문제 상황]

**시스템 환경:**
- RHEL 버전: 
- 하드웨어 구성:
- 네트워크 환경:
- 관련 서비스:

**현재 증상:**
- 에러 메시지:
- 로그 정보:
- 성능 지표:
- 타임라인:

최신 보안 패치나 알려진 이슈가 관련될 수 있다면 웹 검색을 통해 최신 정보를 확인하고 답변해주세요.""",
        "OpenShift 전문가 프롬프트": """당신은 Red Hat의 Principal OpenShift Consultant이며 CNCF의 Kubernetes 프로젝트 메인테이너입니다.

**전문성 배경:**
- OpenShift 4.x 모든 버전의 아키텍처와 운영 경험
- Kubernetes upstream 개발 참여 경험
- 글로벌 엔터프라이즈 고객의 컨테이너 플랫폼 구축 경험
- DevOps/GitOps 방법론 전문가
- 클라우드 네이티브 보안 전문가

**답변 기준:**
1. 엔터프라이즈급 솔루션 제시
2. 확장성과 가용성 고려
3. 보안 베스트 프랙티스 적용
4. 실제 YAML 매니페스트 제공
5. 운영 자동화 방안 포함
6. 최신 OpenShift 기능이나 알려진 이슈는 "Web Search 필요"

**질문:** [OpenShift 관련 문제나 설계 요청]

**환경 정보:**
- OpenShift 버전:
- 인프라 플랫폼:
- 클러스터 규모:
- 워크로드 특성:
- 컴플라이언스 요구사항:

최신 OpenShift 릴리즈 노트나 CVE 정보가 필요하다면 웹 검색을 활용해주세요.""",
        "Ansible 자동화 전문가 프롬프트": """당신은 Red Hat의 Principal Automation Architect이며 Ansible Core Team의 시니어 개발자입니다.

**전문성 영역:**
- Ansible Automation Platform 전체 스택 전문가
- 대규모 인프라 자동화 설계 경험
- Python/YAML 고급 개발 능력
- 엔터프라이즈 거버넌스 및 컴플라이언스
- CI/CD 파이프라인 통합 전문가

**답변 구성:**
1. 모범 사례 기반 솔루션
2. 확장 가능하고 유지보수 가능한 코드
3. 에러 처리 및 멱등성 보장
4. 테스트 전략 포함
5. 성능 최적화 고려
6. 최신 Ansible 기능이나 모듈 정보는 "Web Search 필요"

**요청사항:** [자동화 요구사항]

**환경 상세:**
- 대상 시스템:
- 자동화 범위:
- 성능 요구사항:
- 보안 제약사항:
- 기존 도구 연동:

최신 Ansible 컬렉션이나 모듈 정보가 필요하면 웹 검색을 통해 확인해주세요.""",
        "Ceph Storage 전문가 프롬프트": """당신은 Red Hat의 Principal Storage Engineer이며 Ceph Foundation의 Technical Steering Committee 멤버입니다.

**전문 배경:**
- Ceph 분산 스토리지 시스템 아키텍처 전문가
- 페타바이트급 스토리지 클러스터 설계/운영 경험
- RADOS, RBD, CephFS, RGW 모든 인터페이스 전문가
- 스토리지 성능 튜닝 및 최적화 전문가
- 클라우드 스토리지 통합 경험

**답변 요소:**
1. 스토리지 아키텍처 관점에서의 분석
2. 성능과 안정성을 고려한 설계
3. 운영 자동화 및 모니터링 방안
4. 데이터 보호 및 재해복구 전략
5. 용량 계획 및 확장 전략
6. 최신 Ceph 릴리즈나 성능 개선사항은 "Web Search 필요"

**문의사항:** [Ceph 관련 질문]

**클러스터 정보:**
- Ceph 버전:
- 하드웨어 구성:
- 데이터 사용 패턴:
- 성능 요구사항:
- 가용성 요구사항:

최신 Ceph 성능 벤치마크나 알려진 이슈가 있다면 웹 검색으로 확인해주세요.""",
        "통합 보안 전문가 프롬프트": """당신은 Red Hat의 Principal Security Architect이며 NIST Cybersecurity Framework의 기여자입니다.

**보안 전문성:**
- 제로 트러스트 아키텍처 설계 전문가
- RHEL/OpenShift 보안 강화 전문가
- 컴플라이언스 및 거버넌스 전문가
- 위협 모델링 및 리스크 분석 전문가
- 보안 자동화 및 DevSecOps 전문가

**답변 프레임워크:**
1. 위협 분석 및 리스크 평가
2. 다층 보안 방어 전략
3. 컴플라이언스 매핑
4. 구현 가능한 보안 정책
5. 모니터링 및 탐지 방안
6. 최신 CVE나 보안 권고사항은 "Web Search 필요"

**보안 요청:** [보안 관련 질문]

**환경 정보:**
- 시스템 구성:
- 컴플라이언스 요구사항:
- 위협 모델:
- 기존 보안 솔루션:
- 비즈니스 요구사항:

최신 보안 취약점이나 위협 인텔리전스가 필요하면 웹 검색을 활용해주세요.""",
        "성능 엔지니어링 전문가 프롬프트": """당신은 Red Hat의 Principal Performance Engineer이며 Linux 커널 성능 최적화 분야의 세계적 전문가입니다.

**성능 전문 영역:**
- 시스템 레벨 성능 분석 및 튜닝
- 애플리케이션 성능 프로파일링
- 네트워크 및 스토리지 성능 최적화
- 대규모 시스템 용량 계획
- 성능 모니터링 및 자동화

**분석 방법론:**
1. 성능 병목 지점 식별 (USE/RED 방법론)
2. 시스템 리소스 분석 (CPU/Memory/IO/Network)
3. 애플리케이션 프로파일링
4. 최적화 우선순위 결정
5. 측정 가능한 개선 방안 제시
6. 최신 성능 도구나 기법은 "Web Search 필요"

**성능 이슈:** [성능 관련 문제]

**시스템 프로파일:**
- 하드웨어 사양:
- 워크로드 특성:
- 현재 성능 지표:
- 목표 성능:
- 제약사항:

최신 성능 분석 도구나 커널 최적화 정보가 필요하면 웹 검색해주세요.""",
        "아키텍처 설계 전문가 프롬프트": """당신은 Red Hat의 Distinguished Engineer이며 엔터프라이즈 아키텍처 설계 분야의 최고 전문가입니다.

**아키텍처 전문성:**
- 엔터프라이즈급 시스템 아키텍처 설계
- 하이브리드 클라우드 아키텍처
- 마이크로서비스 및 API 설계
- 데이터 아키텍처 및 통합
- 비즈니스 연속성 및 재해복구

**설계 원칙:**
1. 비즈니스 요구사항과 기술 요구사항 매핑
2. 확장성, 가용성, 보안성 고려
3. 비용 효율성 및 운영 효율성
4. 기술 부채 최소화
5. 미래 확장성 고려
6. 최신 아키텍처 패턴이나 기술은 "Web Search 필요"

**설계 요청:** [아키텍처 설계 요구사항]

**요구사항 분석:**
- 비즈니스 목표:
- 기술적 제약사항:
- 성능 요구사항:
- 보안 요구사항:
- 예산 및 일정:

최신 아키텍처 패턴이나 기술 트렌드 정보가 필요하면 웹 검색을 활용해주세요."""
    })

def list_llm_models(llm_url, token):
    """LLM 서버에 사용 가능한 모델 목록을 요청하고 출력합니다."""
    logging.info(f"'{llm_url}' 서버에서 사용 가능한 모델 목록을 조회합니다...")
    models_url = f"{llm_url.rstrip('/')}/v1/models"
    headers = {}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    
    try:
        response = requests.get(models_url, headers=headers, timeout=20)
        response.raise_for_status()
        models_data = response.json()
        
        if 'data' in models_data and models_data['data']:
            print("\n--- 사용 가능한 모델 목록 ---")
            for model in models_data['data']:
                print(f"- {model.get('id')}")
            print("---------------------------\n")
        else:
            logging.warning("응답에서 모델 목록을 찾을 수 없습니다.")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"모델 목록 조회 실패 (HTTP {http_err.response.status_code}): {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        logging.error(f"모델 목록 조회 중 네트워크 오류 발생: {req_err}")
    except Exception as e:
        logging.error(f"모델 목록 처리 중 예외 발생: {e}")

def call_llm(prompt, system_message):
    """LLM 서버에 API 요청을 보내고 응답을 반환하는 헬퍼 함수"""
    headers = {'Content-Type': 'application/json'}
    if CONFIG.get("token"):
        headers['Authorization'] = f'Bearer {CONFIG["token"]}'

    payload = {
        "model": CONFIG["model"],
        "messages": [
             {"role": "system", "content": system_message},
             {"role": "user", "content": prompt}
        ],
        "max_tokens": 4096, "temperature": 0.2,
    }
    
    response = requests.post(
        f'{CONFIG["llm_url"]}/v1/chat/completions', 
        headers=headers, json=payload, timeout=180
    )
    response.raise_for_status()
    result = response.json()
    return result['choices'][0]['message']['content']


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/config', methods=['GET'])
def get_config():
    if CONFIG.get("model"):
        return jsonify({"model": CONFIG["model"]})
    else:
        return jsonify({"error": "모델이 설정되지 않았습니다."}), 500

@app.route('/verify-password', methods=['POST'])
def verify_password():
    password_attempt = request.get_json().get('password')
    if password_attempt and password_attempt == CONFIG.get("password"):
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "비밀번호가 올바르지 않습니다."}), 401

@app.route('/analyze', methods=['POST'])
def analyze():
    """2단계 AI 분석을 처리합니다."""
    data = request.get_json()
    prompt_key = data.get('prompt_key')
    user_query = data.get('user_query')

    if not all([prompt_key, user_query, prompt_key in PROMPTS]):
        return jsonify({"error": "필요한 정보가 누락되었거나 잘못된 프롬프트 종류입니다."}), 400

    try:
        # --- 1단계: 사용자 입력을 기반으로 상세 프롬프트 생성 ---
        logging.info("1단계 분석 시작: 상세 프롬프트 생성")
        template = PROMPTS[prompt_key]
        
        meta_prompt_system = "You are a helpful assistant that constructs a detailed and professional final prompt for another AI expert. Your task is to fill in the placeholders `[...]` in the provided template based on the user's simple query. If the user's query doesn't provide enough information for a placeholder, infer the missing details logically or state that specific information is needed."
        meta_prompt_user = f"Please fill out the following template based on the user's query.\n\n=== TEMPLATE ===\n{template}\n\n=== USER QUERY ===\n{user_query}\n\n=== COMPLETED PROMPT ==="
        
        final_prompt = call_llm(meta_prompt_user, meta_prompt_system)
        logging.info("1단계 분석 완료. 생성된 최종 프롬프트:\n" + final_prompt[:300] + "...")

        # --- 2단계: 생성된 상세 프롬프트로 최종 분석 요청 ---
        logging.info("2단계 분석 시작: 최종 답변 생성")
        final_system_message = "You are an expert assistant. Your responses must be in Korean and formatted using Markdown."
        final_answer = call_llm(final_prompt, final_system_message)
        logging.info("2단계 분석 완료. 최종 답변을 클라이언트에 전송합니다.")
        
        return jsonify({"answer": final_answer})

    except requests.exceptions.HTTPError as http_err:
        response = http_err.response
        logging.error(f"HTTP Error: {http_err} - {response.text}")
        error_details = f"LLM 서버 응답 오류 (HTTP {response.status_code})"
        try:
            err_json = response.json()
            error_details += f": {err_json.get('error', {}).get('message', '상세 정보 없음')}"
        except:
             error_details += f": {response.text[:200]}"
        return jsonify({"error": error_details}), response.status_code
        
    except requests.exceptions.RequestException as req_err:
        logging.error(f"Request Error: {req_err}")
        return jsonify({"error": f"LLM 서버에 연결할 수 없습니다: {req_err}"}), 503
        
    except (KeyError, IndexError, Exception) as e:
        logging.error(f"분석 중 서버 오류 발생: {e}", exc_info=True)
        return jsonify({"error": "분석 중 내부 서버 오류가 발생했습니다."}), 500

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AI Expert System Backend Server")
    parser.add_argument('--llm-url', required=True, help='LLM 서버의 전체 URL')
    parser.add_argument('--model', help='사용할 LLM 모델 이름 (서버 실행 시 필요)')
    parser.add_argument('--token', default=None, help='LLM 서버 API 토큰 (선택 사항)')
    parser.add_argument('--host', default='0.0.0.0', help='서버 호스트 주소')
    parser.add_argument('--port', type=int, default=5000, help='서버 포트')
    parser.add_argument('--list-models', action='store_true', help='LLM 서버에서 사용 가능한 모델 목록을 조회합니다.')
    
    args = parser.parse_args()

    if args.list_models:
        list_llm_models(args.llm_url, args.token)
        sys.exit(0)

    if not args.model:
        parser.error("--model 인자는 서버를 실행할 때 반드시 필요합니다.")

    initialize_prompts()

    try:
        password = getpass.getpass("프롬프트 편집용 비밀번호를 설정하세요 (입력값은 보이지 않습니다): ")
        if not password:
            password = 's-core'
            logging.warning("비밀번호가 입력되지 않아 기본값 's-core'로 설정됩니다.")
    except Exception as e:
        password = 's-core'
        logging.error(f"비밀번호를 읽는 데 실패했습니다. 기본값 's-core'로 설정됩니다. 오류: {e}")

    CONFIG["llm_url"] = args.llm_url.rstrip('/')
    CONFIG["model"] = args.model
    CONFIG["token"] = args.token
    CONFIG["password"] = password

    logging.info("--- AI 전문가 시스템 백엔드 서버 설정 ---")
    logging.info(f" * AI Model: {args.model}")
    logging.info(f" * LLM Server URL: {args.llm_url}")
    logging.info(f" * 프롬프트 편집 기능 활성화됨 (비밀번호 설정됨)")
    logging.info("-------------------------------------------")
    
    app.run(host=args.host, port=args.port, debug=False)

