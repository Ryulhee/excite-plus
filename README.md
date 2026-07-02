# EXCITE plus Frontend Prototype

정적 HTML 프론트엔드 확인용 파일입니다. 이번 버전은 데모 데이터 없이 초기 운영 전 상태를 기준으로 구성했으며, 백엔드 연결 전 기능 검증을 위해 `assets/app.js`에 localStorage 기반 내부 기능을 추가했습니다.

## 반영 사항

- 좌측/상단 로고 텍스트는 `EXCITE plus`만 표시
- 모든 예시 대상자, Vital 파일, 태그, 분석 결과를 제거하고 0/빈 상태로 표시
- 대시보드의 파일 처리 현황을 미태그 Vital 확인용 원형 그래프로 변경
- 하단 문구를 EXCITE 팀 정보와 주소로 변경
- 연구 데이터 업로드는 태그 선택 후 환자정보/임상자료/custom table을 고르는 흐름으로 수정
- Vital 업로드는 `.vital` 원본 파일 일괄 업로드 전용으로 수정
- CSV/Excel/원본 vital 선택은 업로드가 아니라 내보내기/다운로드 단계로 분리
- 파일 등록대장은 빈 운영 상태와 긴 단일 행 헤더를 유지하도록 수정
- 매칭, 태그 관리, 결과, audit 등 모든 페이지에서 더미 데이터를 제거
- 통계 분석 화면은 LMM 고정이 아니라 분석 방법을 선택하고, 그래프는 점 크기/선 두께/CI 음영 등 논문용 스타일을 조정하는 구조로 변경
- 태그는 연구를 구분하는 큰 라벨로 유지하고, Day/group/visit/stage 등은 태그 내부 분류축과 표준값으로 관리

## 이번 JS 기능

- `localStorage` 기반 연구 태그 생성/수정/삭제
- 태그 내부 분류축 생성 및 표준값/동의어 저장
- `.vital` 파일 다중 선택/드래그 앤 드롭 업로드 목록 생성
- Vital 파일 등록대장 검색/상태 필터/태그 필터/삭제
- 연구자료 직접 입력 화면에서 custom variable 추가/삭제
- 태그 부여 화면에서 Vital 파일 또는 연구자료 변수에 연구 태그와 내부 구분값 저장
- 환자/파일 매칭 화면에서 선택한 Vital 파일에 가명 대상자 ID, 이벤트 ID, custom key 저장
- 통계 분석 화면에서 연구 태그, x축, y축, 분석 방법, 그래프 스타일 선택 및 분석 설정 저장
- 분석 결과 목록, 대시보드, audit log 일부 자동 갱신
- 내보내기 화면에서 현재 localStorage 데이터를 CSV/JSON manifest로 다운로드

## 확인 시작점

- `login.html`
- `dashboard.html`
- `tag-manager.html`
- `vital-upload.html`
- `vital-registry.html`
- `patient-upload.html`
- `tag-assignment.html`
- `patient-matching.html`
- `statistical-analysis.html`
- `export-center.html`

## 주의

현재는 서버/API/DB 없이 브라우저 저장소에만 저장되는 프론트엔드 프로토타입입니다. 브라우저 캐시 또는 localStorage를 지우면 입력한 테스트 데이터가 사라집니다. 실제 `.vital` 원본 파일 자체는 브라우저 localStorage에 저장하지 않고, 프론트에서는 파일 메타데이터와 처리 상태만 저장합니다.
