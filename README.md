# Universal Log Analyzer v2

> 텍스트 로그 파일(.txt) 및 CSV 파일을 업로드하면 AI가 자동으로 분석하여 진단 결과와 고객사 전달용 이메일 초안을 생성하는 웹 서비스입니다. 기존 BSOD 덤프 분석 엔진에서 다목적 로그 분석 플랫폼으로 진화했습니다.

[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 주요 기능

| 기능 | 설명 |
|------|------|
| **로그 파일 업로드** | 드래그앤드롭 지원, `.txt` 및 `.csv` 형식 허용 |
| **대용량 파일 지원** | 최대 2GB 파일의 청크 업로드(재개 지원) 및 스트리밍 처리 |
| **자동 인코딩 감지** | UTF-8, UTF-16 등 다양한 텍스트 인코딩 자동 인식 |
| **Bug Check 연동** | 텍스트 내 BugCheck 코드가 존재할 경우 자동 추출 및 60+개 DB와 매칭 |
| **AI 진단 (Puter.js)** | 브라우저 내장 Puter.js를 활용한 무료 AI 근본 원인 분석 및 해결책 제시 |
| **이메일 생성** | 고객사 전달용 이메일 초안 자동 생성 (한/영, 톤 선택) |
| **PowerShell 자동화** | `BSOD-AutoWindbg.ps1` 스크립트를 통한 WinDbg 분석 자동화 및 결과 자동 업로드 |
| **Swagger UI** | 전체 REST API 문서 및 인터랙티브 테스트 환경 |

---

## 아키텍처 개요

1. **클라이언트 (브라우저)**: `index.html` 기반의 단일 페이지 애플리케이션(SPA)
   - 대용량 파일 청크 분할 및 업로드 관리
   - Puter.js 기반 클라이언트 사이드 AI 추론 (서버 비용/API 키 불필요)
2. **API 서버 (FastAPI)**: 
   - 청크 업로드 세션 관리 및 파일 조립 (`/tmp` 디렉토리 활용)
   - 텍스트/CSV 파일 파싱 및 메타데이터 추출
   - BugCheck DB 제공
3. **자동화 스크립트**:
   - `BSOD-AutoWindbg.ps1`: 로컬 머신에서 WinDbg를 백그라운드로 실행하여 크래시 덤프를 텍스트 로그로 변환한 뒤, `/api/upload/direct`로 전송하여 웹 분석 화면을 즉시 띄웁니다.

---

## Swagger UI란?

**Swagger UI**(`/api/docs`)는 이 서비스의 모든 REST API 엔드포인트를 **브라우저에서 직접 테스트**할 수 있는 인터랙티브 문서 페이지입니다.

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

# 서버 실행
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

브라우저에서 `http://localhost:8000` 접속

### 2. 자동화 스크립트 사용법 (Windows)

관리자 권한으로 PowerShell을 열고 다음 스크립트를 실행합니다:

```powershell
.\BSOD-AutoWindbg.ps1
```
1. 덤프 파일(`.dmp`) 선택 창이 나타납니다.
2. 스크립트가 로컬에 설치된 WinDbg를 찾아 백그라운드에서 자동 분석을 수행합니다.
3. 분석이 완료된 텍스트 로그 파일이 서버로 업로드되며, 자동으로 웹 브라우저가 열려 AI 진단 결과를 보여줍니다.

### 3. Vercel 배포

```bash
# Vercel CLI 설치
npm install -g vercel

# 배포
vercel --prod
```

> **주의**: Vercel 서버리스 환경에서는 `/tmp` 디렉토리만 쓰기 가능하며, 최대 요청 크기 제한(4.5MB)이 있습니다. 대용량 파일은 자동으로 청크 분할되어 업로드됩니다.

---

## API 엔드포인트 목록

### Upload (청크 및 다이렉트)
| Method | Path | 설명 |
|--------|------|------|
| POST | `/api/upload/direct` | 소형 로그 파일 직접 업로드 (스크립트 연동용) |
| POST | `/api/upload/init` | 대용량 청크 업로드 세션 초기화 |
| POST | `/api/upload/chunk/{upload_id}` | 청크 업로드 (최대 4MB 단위) |
| GET | `/api/upload/status/{upload_id}` | 업로드 진행 상태 |
| POST | `/api/upload/complete` | 업로드 완료 및 파일 조립 |

### Analysis
| Method | Path | 설명 |
|--------|------|------|
| POST | `/api/analyze` | 텍스트/CSV 직접 업로드 분석 (≤4MB) |
| POST | `/api/analyze/by-upload-id/{id}` | 청크 업로드 완료 후 분석 |

### Bug Check Database
| Method | Path | 설명 |
|--------|------|------|
| GET | `/api/bugchecks` | 전체 코드 목록 (필터링 지원) |
| GET | `/api/bugcheck/{code}` | 특정 코드 상세 정보 |

---

## 지원 로그 형식

| 확장자 | 인코딩 | 설명 |
|------|----------|------|
| `.txt` | UTF-8, UTF-16 | 일반 텍스트 로그, WinDbg 출력 로그, 시스템 이벤트 로그 등 |
| `.csv` | UTF-8 | 쉼표로 구분된 데이터 로그 |

---

## 프로젝트 구조

```
bsod-analyzer-v2/
├── api/
│   └── main.py              # FastAPI 애플리케이션 및 API 라우터
├── engine/
│   ├── dump_analyzer.py     # 텍스트 로그 및 메타데이터 파싱 엔진
│   ├── bugcheck_db.py       # Bug Check 코드 DB (60+개)
│   └── __init__.py
├── frontend/
│   └── index.html           # 클라이언트 사이드 AI 및 UI가 포함된 SPA
├── BSOD-AutoWindbg.ps1      # WinDbg 자동화 및 웹 업로드 연동 스크립트
├── requirements.txt
├── vercel.json
└── README.md
```

---

## 라이선스

MIT License — 자유롭게 사용, 수정, 배포 가능합니다.
