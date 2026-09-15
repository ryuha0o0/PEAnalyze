# PEAnalyze

생성형AI를 활용한 악성코드 분석 및 대응 과제 1.
PE 정적 특징 추출기 작성과 생성형AI 분석 결과 검증.

## 구성

| 파일 | 설명 |
|---|---|
| `extract_features.py` | PE 정적 특징 추출 스크립트 (MZ/PE 검증, 32/64비트 판별, 섹션 엔트로피 직접 구현, Import/의심 API 대조) |
| `PE_6/` | 강사가 배포한 PE 샘플 6개(정상 3 / 악성 의심 3)와 해시 목록(`SHA256SUMS.txt`) |
| `features.csv` | 스크립트 실행 결과 (샘플 6개, 1행/샘플) |
| `REPORT.md` | 샘플별 판정 근거, 생성형AI 검증 표, 오탐 가능성 논의를 포함한 보고서 |
| `requirements.txt` | 의존 패키지 (`pefile`) |

## 실행 방법

```bash
pip install -r requirements.txt
python extract_features.py            # 인자 생략 시 PE_6/ -> features.csv
python extract_features.py <샘플_디렉터리> <출력_csv_경로>   # 다른 경로 지정 시
```

엔트로피 계산은 요구사항에 따라 외부 라이브러리 없이 직접 구현했으며
(`calc_shannon_entropy` 함수), 섹션/Import 파싱에는 `pefile` 을 사용했다.

## 안전 수칙

악성으로 의심되는 샘플은 이 저장소의 어떤 코드로도 실행하지 않는다. 모든
분석은 파일을 바이트 단위로 읽거나 `pefile` 로 헤더 구조체를 파싱하는
정적 분석으로만 이루어진다. 실제 분석 작업은 네트워크가 차단된 격리
환경에서 수행할 것을 권장한다.
