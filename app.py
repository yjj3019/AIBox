<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 기반 전문가 시스템</title>
    <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #007bff;
            --secondary-color: #6c757d;
            --background-color: #f0f4f8;
            --surface-color: #ffffff;
            --text-color: #212529;
            --header-bg: #0d1b2a;
            --header-text: #ffffff;
            --border-color: #dee2e6;
            --shadow: 0 4px 12px rgba(0,0,0,0.08);
            --code-bg: #282c34;
            --code-text: #abb2bf;
        }

        body {
            font-family: 'Noto Sans KR', sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }

        .container {
            background: var(--surface-color);
            border-radius: 12px;
            box-shadow: var(--shadow);
            width: 100%;
            max-width: 960px;
            overflow: hidden;
        }

        .header {
            background-color: var(--header-bg);
            color: var(--header-text);
            padding: 2rem;
            text-align: center;
        }
        .header h1 { margin: 0; font-size: 2rem; font-weight: 700; }
        .header p { margin: 0.5rem 0 0; font-size: 1rem; opacity: 0.8; }
        
        /* --- 상태 표시줄 개선 --- */
        #status { 
            padding: 0.75rem 2rem; 
            font-size: 0.9rem; 
            text-align: right; 
            background-color: #e9ecef; 
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 1.5rem;
        }
        .status-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .status-indicator {
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }
        .status-indicator.connected { background-color: #28a745; }
        .status-indicator.disconnected { background-color: #dc3545; }

        .content { padding: 2rem; }
        .card { background: var(--surface-color); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
        
        h2 {
            font-size: 1.25rem;
            margin-top: 0;
            margin-bottom: 1rem;
            color: var(--header-bg);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #f0f4f8;
            padding-bottom: 0.5rem;
        }

        select, textarea {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 0.95rem;
            box-sizing: border-box;
            margin-bottom: 1rem;
            font-family: 'Noto Sans KR', sans-serif;
        }

        textarea { height: 200px; resize: vertical; }
        .button-group { display: flex; gap: 1rem; margin-top: 1rem; }
        
        .button {
            background-image: linear-gradient(to right, #007bff, #0056b3);
            color: white; border: none; padding: 0.8rem 1.5rem; border-radius: 6px;
            cursor: pointer; font-size: 1rem; font-weight: 500; text-align: center;
            transition: all 0.3s ease; flex-grow: 1; display: inline-flex;
            align-items: center; justify-content: center; gap: 0.5rem;
        }
        .button:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(0, 123, 255, 0.2); }
        .button.secondary { background-image: linear-gradient(to right, #6c757d, #5a6268); }
        .button:disabled { background-image: none; background-color: #cccccc; cursor: not-allowed; transform: none; box-shadow: none; }
        #result-container { display: none; }
        
        #result-output {
            max-height: 500px; overflow-y: auto; line-height: 1.8;
            word-wrap: break-word; padding: 1.5rem; background-color: #fdfdfd; 
            border-radius: 6px; border: 1px solid var(--border-color);
        }
        #result-output h1, #result-output h2, #result-output h3, #result-output h4 { 
            margin-top: 2em; margin-bottom: 0.8em; border-bottom: 1px solid #eee; 
            padding-bottom: 0.4em; color: #1a2c42; font-weight: 600;
        }
        #result-output h1 { font-size: 1.6em; }
        #result-output h2 { font-size: 1.4em; }
        #result-output h3 { font-size: 1.2em; }
        #result-output table { 
            border-collapse: collapse; width: 100%; margin: 1.5em 0; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.05); border: 1px solid #ddd;
        }
        #result-output th, #result-output td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        #result-output th { background-color: #f8f9fa; font-weight: 600; }
        #result-output tr:nth-child(even) { background-color: #fcfcfc; }
        #result-output p { margin-bottom: 1em; }
        #result-output ul, #result-output ol { padding-left: 2em; }
        #result-output code:not(pre > code) { 
            background-color: #eef8ff; color: #0056b3; padding: 3px 6px; 
            border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; 
        }
        #result-output pre { 
            position: relative; background-color: var(--code-bg); color: var(--code-text);
            padding: 1.5rem 1rem; border-radius: 8px; overflow-x: auto; 
            margin: 1.5em 0; font-family: 'JetBrains Mono', monospace; line-height: 1.6;
        }
        #result-output pre code { background-color: transparent; padding: 0; color: inherit; font-family: inherit; }
        .copy-code-btn {
            position: absolute; top: 10px; right: 10px; background-color: #555;
            color: white; border: none; padding: 5px 10px; border-radius: 5px;
            cursor: pointer; opacity: 0.7; transition: all 0.2s; font-size: 0.8em;
        }
        .copy-code-btn:hover { opacity: 1; background-color: var(--primary-color); }
        
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); backdrop-filter: blur(5px); }
        .modal-content { background-color: var(--surface-color); margin: 10% auto; padding: 2rem; border: none; width: 80%; max-width: 700px; border-radius: 10px; box-shadow: 0 8px 30px rgba(0,0,0,0.2); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem; margin-bottom: 1.5rem; }
        .close-button { color: #aaa; font-size: 28px; font-weight: bold; cursor: pointer; }
        .prompt-edit-item { margin-bottom: 1.5rem; }
        .prompt-edit-item label { display: block; font-weight: 500; margin-bottom: 0.5rem; }
        .prompt-edit-item textarea { height: 120px; }
        
        .edit-button {
            padding: 0.5rem 1rem; font-size: 0.85rem; cursor: pointer; border: 1px solid var(--border-color);
            background-color: var(--surface-color); border-radius: 6px; color: var(--primary-color);
            transition: all 0.2s; display: inline-flex; align-items: center; gap: 0.4rem;
        }
        .edit-button:hover { background-color: #eef8ff; border-color: var(--primary-color); }
        .icon { width: 1em; height: 1em; }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>AI 기반 전문가 시스템</h1>
            <p>척척 박사 유박사에게 질문하세요.</p>
        </header>
        <div id="status">
            <div class="status-item">
                <span>LLM 연결 상태:</span>
                <span id="conn-status-indicator" class="status-indicator"></span>
                <span id="conn-status">확인 중...</span>
            </div>
            <div class="status-item">
                <span>현재 AI 모델:</span>
                <span id="model-name">N/A</span>
            </div>
        </div>

        <div class="content">
            <div class="card">
                <h2>
                    <span>분석 프롬프트 선택</span>
                    <button id="edit-prompts-btn" class="edit-button">
                        <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path d="M17.414 2.586a2 2 0 00-2.828 0L7 10.172V13h2.828l7.586-7.586a2 2 0 000-2.828z"></path><path fill-rule="evenodd" d="M2 6a2 2 0 012-2h4a1 1 0 010 2H4v10h10v-4a1 1 0 112 0v4a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" clip-rule="evenodd"></path></svg>
                        프롬프트 편집
                    </button>
                </h2>
                <select id="prompt-select"></select>
                <textarea id="question-input" placeholder="이곳에 해결하고 싶은 문제나 분석 내용을 자유롭게 입력하세요. AI가 필요한 정보를 파악하여 프롬프트를 구성합니다."></textarea>
                
                <div class="button-group">
                    <button id="submit-btn" class="button">
                        <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 1.414L10.586 9H7a1 1 0 100 2h3.586l-1.293 1.293a1 1 0 101.414 1.414l3-3a1 1 0 000-1.414z" clip-rule="evenodd"></path></svg>
                        AI 분석 요청
                    </button>
                    <button id="clear-btn" class="button secondary">
                        <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm4 0a1 1 0 012 0v6a1 1 0 11-2 0V8z" clip-rule="evenodd"></path></svg>
                        질문 삭제
                    </button>
                </div>
            </div>

            <div id="result-container" class="card">
                <h2>AI 분석 결과</h2>
                <div id="result-output"></div>
                <div class="button-group" style="justify-content: flex-end;">
                     <button id="save-html-btn" class="button secondary" style="flex-grow: 0; display: none;">
                        <svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z" clip-rule="evenodd"></path></svg>
                         HTML로 저장
                     </button>
                </div>
            </div>
        </div>
    </div>
    
    <div id="prompt-modal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 style="border:none; margin:0; padding:0;">프롬프트 편집</h2>
                <span class="close-button">&times;</span>
            </div>
            <div id="modal-body"></div>
        </div>
    </div>

<script>
let prompts = {
    "시스템 문제 해결 전문가 프롬프트": `당신은 20년 경력의 Red Hat Certified Architect (RHCA)이자 Linux Foundation의 Technical Advisory Board 멤버입니다. 

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

최신 보안 패치나 알려진 이슈가 관련될 수 있다면 웹 검색을 통해 최신 정보를 확인하고 답변해주세요.`,
    "OpenShift 전문가 프롬프트": `당신은 Red Hat의 Principal OpenShift Consultant이며 CNCF의 Kubernetes 프로젝트 메인테이너입니다.

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

최신 OpenShift 릴리즈 노트나 CVE 정보가 필요하다면 웹 검색을 활용해주세요.`,
    "Ansible 자동화 전문가 프롬프트": `당신은 Red Hat의 Principal Automation Architect이며 Ansible Core Team의 시니어 개발자입니다.

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

최신 Ansible 컬렉션이나 모듈 정보가 필요하면 웹 검색을 통해 확인해주세요.`,
    "Ceph Storage 전문가 프롬프트": `당신은 Red Hat의 Principal Storage Engineer이며 Ceph Foundation의 Technical Steering Committee 멤버입니다.

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

최신 Ceph 성능 벤치마크나 알려진 이슈가 있다면 웹 검색으로 확인해주세요.`,
    "통합 보안 전문가 프롬프트": `당신은 Red Hat의 Principal Security Architect이며 NIST Cybersecurity Framework의 기여자입니다.

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

최신 보안 취약점이나 위협 인텔리전스가 필요하면 웹 검색을 활용해주세요.`,
    "성능 엔지니어링 전문가 프롬프트": `당신은 Red Hat의 Principal Performance Engineer이며 Linux 커널 성능 최적화 분야의 세계적 전문가입니다.

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

최신 성능 분석 도구나 커널 최적화 정보가 필요하면 웹 검색해주세요.`,
    "아키텍처 설계 전문가 프롬프트": `당신은 Red Hat의 Distinguished Engineer이며 엔터프라이즈 아키텍처 설계 분야의 최고 전문가입니다.

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

최신 아키텍처 패턴이나 기술 트렌드 정보가 필요하면 웹 검색을 활용해주세요.`
};

const connStatusIndicator = document.getElementById('conn-status-indicator');
const connStatusSpan = document.getElementById('conn-status');
const modelNameSpan = document.getElementById('model-name');
const promptSelect = document.getElementById('prompt-select');
const questionInput = document.getElementById('question-input');
const submitBtn = document.getElementById('submit-btn');
const clearBtn = document.getElementById('clear-btn');
const resultContainer = document.getElementById('result-container');
const resultOutput = document.getElementById('result-output');
const saveHtmlBtn = document.getElementById('save-html-btn');
const editPromptsBtn = document.getElementById('edit-prompts-btn');
const promptModal = document.getElementById('prompt-modal');
const modalBody = document.getElementById('modal-body');
const closeModalBtn = document.querySelector('.close-button');

function loadPromptsFromStorage() {
    const savedPrompts = localStorage.getItem('customPrompts');
    if (savedPrompts) {
        try {
            prompts = JSON.parse(savedPrompts);
        } catch(e) {
            console.error("Error parsing prompts from localStorage", e);
            localStorage.removeItem('customPrompts');
        }
    }
}

function populatePrompts() {
    promptSelect.innerHTML = '';
    for (const key in prompts) {
        const option = document.createElement('option');
        option.value = key;
        option.textContent = key;
        promptSelect.appendChild(option);
    }
    updateQuestionTemplate();
}

function updateQuestionTemplate() {
    questionInput.value = '';
}

async function fetchConfig() {
    try {
        const response = await fetch('/config');
        if (!response.ok) throw new Error(`Server responded with ${response.status}`);
        const data = await response.json();
        if (data.model) {
            modelNameSpan.textContent = data.model;
            connStatusSpan.textContent = "연결됨";
            connStatusIndicator.className = 'status-indicator connected';
        } else {
            throw new Error('Model name not in response');
        }
    } catch (error) {
        modelNameSpan.textContent = 'N/A';
        connStatusSpan.textContent = '연결 실패';
        connStatusIndicator.className = 'status-indicator disconnected';
        console.error('Failed to fetch config:', error);
    }
}

async function submitAnalysis() {
    const userQuery = questionInput.value;
    const promptKey = promptSelect.value;
    if (!userQuery.trim()) {
        alert("분석할 내용을 입력해주세요.");
        return;
    }
    setLoading(true);
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ prompt_key: promptKey, user_query: userQuery }),
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({ error: 'Cannot parse server error response.' }));
            throw new Error(errorData.error || `Server error: ${response.status}`);
        }
        const data = await response.json();
        displayResult(data.answer);
    } catch (error) {
        displayResult(`**오류가 발생했습니다:**\n\n\`\`\`\n${error.message}\n\`\`\``);
    } finally {
        setLoading(false);
    }
}

function addCopyButtons(container) {
    const pres = container.querySelectorAll('pre');
    pres.forEach(pre => {
        if (pre.querySelector('.copy-code-btn')) return; // 이미 버튼이 있으면 추가하지 않음
        const button = document.createElement('button');
        button.innerText = '복사';
        button.className = 'copy-code-btn';
        pre.appendChild(button);
        button.addEventListener('click', () => {
            const code = pre.querySelector('code');
            navigator.clipboard.writeText(code.innerText).then(() => {
                button.innerText = '복사 완료!';
                setTimeout(() => { button.innerText = '복사'; }, 2000);
            });
        });
    });
}

function displayResult(markdownText) {
    resultContainer.style.display = 'block';
    resultOutput.innerHTML = marked.parse(markdownText || "No content received.");
    addCopyButtons(resultOutput);
    saveHtmlBtn.style.display = 'inline-flex';
}

function setLoading(isLoading) {
    submitBtn.disabled = isLoading;
    if(isLoading) {
        submitBtn.innerHTML = `<svg class="icon" version="1.1" id="L9" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" viewBox="0 0 100 100" enable-background="new 0 0 0 0" xml:space="preserve" style="width: 20px; height: 20px;"><path fill="#fff" d="M73,50c0-12.7-10.3-23-23-23S27,37.3,27,50 M30.9,50c0-10.5,8.5-19.1,19.1-19.1S69.1,39.5,69.1,50"><animateTransform attributeName="transform" attributeType="XML" type="rotate" dur="1s" from="0 50 50" to="360 50 50" repeatCount="indefinite"></animateTransform></path></svg> 분석 중...`;
    } else {
        submitBtn.innerHTML = `<svg class="icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-8.707l-3-3a1 1 0 00-1.414 1.414L10.586 9H7a1 1 0 100 2h3.586l-1.293 1.293a1 1 0 101.414 1.414l3-3a1 1 0 000-1.414z" clip-rule="evenodd"></path></svg> AI 분석 요청`;
    }
}

function clearInputs() {
    questionInput.value = '';
    resultContainer.style.display = 'none';
    resultOutput.innerHTML = '';
    saveHtmlBtn.style.display = 'none';
}

function saveAsHtml() {
    const clone = resultOutput.cloneNode(true);
    clone.querySelectorAll('.copy-code-btn').forEach(btn => btn.remove());
    
    const savedHtmlStyle = `
        <head>
            <meta charset="UTF-8">
            <title>AI 분석 결과</title>
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
            <style>
                body {
                    font-family: 'Noto Sans KR', sans-serif;
                    line-height: 1.8;
                    padding: 2rem;
                    max-width: 800px;
                    margin: auto;
                    color: #212529;
                    background-color: #fdfdfd;
                }
                h1, h2, h3, h4 {
                    color: #1a2c42;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 0.4em;
                    font-weight: 600;
                }
                table {
                    border-collapse: collapse;
                    width: 100%;
                    margin: 1.5em 0;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }
                th { background-color: #f8f9fa; }
                code:not(pre > code) {
                    background-color: #eef8ff;
                    color: #0056b3;
                    padding: 3px 6px;
                    border-radius: 4px;
                    font-family: 'JetBrains Mono', monospace;
                }
                pre {
                    background-color: #282c34;
                    color: #abb2bf;
                    padding: 1.5rem;
                    border-radius: 8px;
                    overflow-x: auto;
                    font-family: 'JetBrains Mono', monospace;
                    line-height: 1.6;
                }
                 pre code {
                    background: none;
                    padding: 0;
                }
            </style>
        </head>
    `;

    const htmlContent = `<!DOCTYPE html><html lang="ko">${savedHtmlStyle}<body><h1>AI 분석 결과</h1><hr>${clone.innerHTML}</body></html>`;
    const blob = new Blob([htmlContent], { type: 'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `AI_분석_결과_${new Date().toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(a.href);
}

function openPromptModal() {
    modalBody.innerHTML = `<p>프롬프트 편집을 위해 비밀번호를 입력하세요.</p><input type="password" id="password-input" style="width:100%;padding:8px;box-sizing:border-box"><p id="password-error" style="color:red;display:none"></p><div class="button-group" style="justify-content:flex-end"><button id="password-submit" class="button" style="flex-grow:0">확인</button></div>`;
    promptModal.style.display = 'block';
    document.getElementById('password-input').focus();
    document.getElementById('password-submit').onclick = async () => {
        const password = document.getElementById('password-input').value;
        const errorEl = document.getElementById('password-error');
        try {
            const response = await fetch('/verify-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const data = await response.json();
            if (data.success) {
                showPromptEditForm();
            } else {
                errorEl.textContent = data.error || '비밀번호가 올바르지 않습니다.';
                errorEl.style.display = 'block';
            }
        } catch (error) {
            errorEl.textContent = '서버 통신 중 오류가 발생했습니다.';
            errorEl.style.display = 'block';
        }
    };
}

function showPromptEditForm() {
    let formHtml = '';
    for (const key in prompts) {
        formHtml += `<div class="prompt-edit-item"><label for="edit-${key}">${key}</label><textarea id="edit-${key}">${prompts[key]}</textarea></div>`;
    }
    formHtml += `<div class="button-group" style="justify-content:flex-end"><button id="save-prompts-btn" class="button" style="flex-grow:0">저장</button><button id="cancel-prompts-btn" class="button secondary" style="flex-grow:0">취소</button></div>`;
    modalBody.innerHTML = formHtml;

    document.getElementById('save-prompts-btn').onclick = () => {
        const newPrompts = {};
        for (const key in prompts) {
            newPrompts[key] = document.getElementById(`edit-${key}`).value;
        }
        prompts = newPrompts;
        localStorage.setItem('customPrompts', JSON.stringify(prompts));
        populatePrompts();
        promptModal.style.display = 'none';
    };
    document.getElementById('cancel-prompts-btn').onclick = () => {
        promptModal.style.display = 'none';
    };
}

window.addEventListener('DOMContentLoaded', () => {
    loadPromptsFromStorage();
    populatePrompts();
    fetchConfig();
});
promptSelect.addEventListener('change', updateQuestionTemplate);
submitBtn.addEventListener('click', submitAnalysis);
clearBtn.addEventListener('click', clearInputs);
saveHtmlBtn.addEventListener('click', saveAsHtml);
editPromptsBtn.addEventListener('click', openPromptModal);
closeModalBtn.addEventListener('click', () => promptModal.style.display = 'none');
window.addEventListener('click', (event) => {
    if (event.target == promptModal) {
        promptModal.style.display = 'none';
    }
});
</script>
</body>
</html>

