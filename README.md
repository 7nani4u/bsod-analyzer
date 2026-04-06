# BSOD Analyzer v2

> Windows 크래시 덤프 파일(.dmp)을 업로드하면 AI가 자동으로 분석하여 진단 결과, 이메일 초안, PDF 보고서를 생성하는 웹 서비스입니다.

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **파일 업로드** | 드래그앤드롭, 최대 2GB, 청크 업로드(재개 지원) |
| **덤프 분석** | 64비트/32비트 커널 덤프, MDMP 사용자 모드 덤프 |
| **Bug Check DB** | 60개 알려진 코드, 원인·수정방법·심각도 포함 |
| **AI 진단** | LLM 기반 근본 원인 분석, 신뢰도 점수, 우선순위 수정 방법 |
| **이메일 생성** | 고객사 전달용 이메일 초안 자동 생성 (한/영, 톤 선택) |
| **PDF 보고서** | 구조화된 PDF 다운로드 (표지, 분석 결과, 시각 자료) |
| **Swagger UI** | 전체 REST API 문서 및 인터랙티브 테스트 환경 |

---

## Swagger UI란?

**Swagger UI**(`/api/docs`)는 이 서비스의 모든 REST API 엔드포인트를 **브라우저에서 직접 테스트**할 수 있는 인터랙티브 문서 페이지입니다.

### Swagger UI가 필요한 이유

```
일반 사용자 → 웹 UI (index.html)
개발자/통합팀 → Swagger UI (/api/docs)
```

Swagger UI를 통해 다음이 가능합니다.

1. **API 탐색** — 모든 엔드포인트의 URL, HTTP 메서드, 파라미터, 응답 스키마를 한눈에 확인
2. **직접 테스트** — 브라우저에서 파일 업로드, JSON 전송 등 실제 API 호출 가능
3. **통합 개발** — 다른 시스템(SIEM, 티켓팅 툴 등)에서 이 API를 호출할 때 참조 문서로 활용
4. **자동 문서화** — 코드 변경 시 문서가 자동으로 업데이트됨

### 접근 방법

| URL | 설명 |
|-----|------|
| `/api/docs` | Swagger UI (인터랙티브, 권장) |
| `/api/redoc` | ReDoc (읽기 전용, 깔끔한 레이아웃) |
| `/api/openapi.json` | OpenAPI 3.0 스키마 (JSON, 자동화 도구용) |

---

## 빠른 시작

### 1. 로컬 실행

```bash
# 저장소 클론
git clone https://github.com/your-org/bsod-analyzer.git
cd bsod-analyzer

# 가상환경 생성 (권장)
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt

# 환경 변수 설정
cp .env.example .env
# .env 파일에서 FORGE_API_KEY 설정 (AI 기능 사용 시)

# 서버 실행
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

브라우저에서 `http://localhost:8000` 접속

### 2. Vercel 배포

```bash
# Vercel CLI 설치
npm install -g vercel

# 환경 변수 설정 (Vercel 대시보드 또는 CLI)
vercel env add FORGE_API_KEY
vercel env add FORGE_API_URL

# 배포
vercel --prod
```

> **주의**: Vercel 서버리스 환경에서는 `/tmp` 디렉토리만 쓰기 가능합니다.
> 대용량 파일(>50MB) 분석 시 타임아웃이 발생할 수 있으므로,
> 별도 분석 서버(Railway, Render 등)를 권장합니다.

### 3. Docker 실행

```bash
docker build -t bsod-analyzer .
docker run -p 8000:8000 -e FORGE_API_KEY=your-key bsod-analyzer
```

---

## API 엔드포인트 목록

### Health
| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/health` | 서비스 상태 및 기능 목록 |

### Upload (청크 업로드, 최대 2GB)
| Method | Path | 설명 |
|--------|------|------|
| POST | `/api/upload/init` | 업로드 세션 초기화 |
| POST | `/api/upload/chunk/{upload_id}` | 청크 업로드 |
| GET | `/api/upload/status/{upload_id}` | 업로드 진행 상태 |
| POST | `/api/upload/complete` | 업로드 완료 및 파일 조립 |
| DELETE | `/api/upload/abort/{upload_id}` | 업로드 중단 및 정리 |

### Analysis
| Method | Path | 설명 |
|--------|------|------|
| POST | `/api/analyze` | 직접 업로드 분석 (≤512MB) |
| POST | `/api/analyze/by-upload-id/{id}` | 청크 업로드 완료 후 분석 |

### Bug Check Database
| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/bugchecks` | 전체 코드 목록 (필터링 지원) |
| GET | `/api/bugcheck/{code}` | 특정 코드 상세 정보 |

### AI Features
| Method | Path | 설명 |
|--------|------|------|
| POST | `/api/ai/diagnose` | LLM AI 진단 |
| POST | `/api/email/generate` | 고객사 이메일 초안 생성 |
| POST | `/api/pdf/generate` | PDF 보고서 다운로드 |
| GET | `/api/pdf/preview/{upload_id}` | PDF HTML 미리보기 |

---

## 분석 결과 JSON 구조

```json
{
  "filename": "memory.dmp",
  "dump_type": "Kernel Minidump (64-bit)",
  "architecture": "x64",
  "file_size_bytes": 524288,
  "analysis_time_seconds": 0.042,
  "crash_summary": {
    "bugcheck_code": "0x0000000A",
    "bugcheck_name": "IRQL_NOT_LESS_OR_EQUAL",
    "bugcheck_description": "A kernel-mode process or driver...",
    "bugcheck_parameters": ["0x0000000000000018", "0x0000000000000002"],
    "severity": "critical",
    "crash_address": "0xFFFFF80012345678",
    "caused_by_driver": "ntoskrnl.exe"
  },
  "system_info": {
    "os_version": "Windows 11 22H2",
    "build_number": "22621",
    "processor_count": 8
  },
  "exception": { "code": "0xC0000005", "address": "0x..." },
  "loaded_modules": [
    { "name": "ntoskrnl.exe", "base_address": "0xFFFFF800...", "size": 10485760 }
  ],
  "diagnosis": {
    "known_causes": ["Faulty device driver", "Memory corruption"],
    "suggested_fixes": ["Update device drivers", "Run Windows Memory Diagnostic"]
  }
}
```

---

## 지원 덤프 형식

| 형식 | 시그니처 | 설명 |
|------|----------|------|
| 64비트 커널 덤프 | `PAGEDU64` | Windows 10/11 커널 미니덤프 |
| 32비트 커널 덤프 | `PAGEDUMP` | Windows 7/8 커널 미니덤프 |
| 사용자 모드 덤프 | `MDMP` | 애플리케이션 크래시 덤프 |

---

## 환경 변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `FORGE_API_KEY` | AI 기능 사용 시 | LLM API 키 (OpenAI 호환) |
| `FORGE_API_URL` | 선택 | LLM API URL (기본: OpenAI) |

---

## 프로젝트 구조

```
bsod-analyzer-v2/
├── api/
│   └── main.py              # FastAPI 애플리케이션 (전체 기능)
├── engine/
│   ├── dump_analyzer.py     # 덤프 파싱 엔진
│   ├── bugcheck_db.py       # Bug Check 코드 DB (60개)
│   └── __init__.py
├── frontend/
│   └── index.html           # 단일 페이지 UI
├── tests/
│   ├── test_analyzer.py     # 단위 테스트 (33개)
│   └── create_sample_dumps.py
├── .github/
│   └── workflows/ci.yml     # GitHub Actions CI
├── .env.example
├── .gitignore
├── requirements.txt
├── vercel.json
└── README.md
```

---

## 라이선스

MIT License — 자유롭게 사용, 수정, 배포 가능합니다.
