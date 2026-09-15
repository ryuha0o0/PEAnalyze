# PE 정적 특징 추출기 작성과 생성형AI 분석 결과 검증 — 보고서

## 1. 개요

강사가 배포한 PE 샘플 6개(정상 3 / 악성 의심 3)를 대상으로 `extract_features.py`
스크립트를 작성해 정적 특징을 추출하고, 그 결과를 `features.csv` 로 저장했다.
이어서 생성형AI에게 각 샘플의 악성 여부 판정을 요청한 뒤, AI가 근거로 제시한
API·섹션·수치가 실제 추출 결과와 일치하는지 대조했다. 검증은 세 가지 조건으로
진행했다.

1. **Claude 블라인드 실험** (정상 샘플 3개 대상, 5.1절): `file`/`strings`
   출력처럼 제한된 정보만 준 뒤 판정을 요청 — AI가 정보가 부족할 때 어떤
   식으로 오판하는지 관찰.
2. **Claude 실제 세션** (정상 샘플 3개 대상, 5.2절): PE 헤더·섹션 플래그·
   문자열을 상세히 제공한 뒤 판정을 요청(수강생이 별도 채팅에서 실제 수행)
   — 정보가 충분할 때도 발생할 수 있는 해석 오류를 검증.
3. **ChatGPT 실제 세션** (악성 의심 샘플 3개 대상, 5.3절): PE 헤더 필드
   (Entry Point, 섹션별 VA/크기/Characteristics, Import, 문자열과 파일
   오프셋)를 상세히 제공한 뒤 판정을 요청(수강생이 실제로 수행) — 정보가
   충분할 때의 인용 정확도를 검증.

분석 대상 6개 샘플은 저장소의 `PE_6/` 디렉터리에 포함되어 있으며, 무결성
확인용 SHA-256 해시는 `PE_6/SHA256SUMS.txt` 에 기록했다. 모든 분석은
파일을 바이트 단위로 읽거나 `pefile` 로 헤더만 파싱하는 **정적 분석**이며,
어떤 샘플도 실행(더블클릭 실행, `subprocess` 호출 등)하지 않았다 —
`extract_features.py` 안에는 파일을 열어서(`open`) 읽거나 `pefile.PE()` 로
헤더 구조체를 파싱하는 코드만 있을 뿐, 샘플을 프로세스로 구동하는 코드는
전혀 없다.

## 2. 추출 방법 요약

- **MZ/PE 시그니처 확인**: 파일의 처음 2바이트가 `MZ` 인지, DOS 헤더
  0x3C 오프셋의 `e_lfanew` 가 가리키는 위치에 `PE\0\0` 시그니처가 있는지
  원시 바이트로 직접 검사했다 (`check_mz_pe_signature`).
- **32/64비트 판별**: `IMAGE_FILE_HEADER.Machine` 값을 확인해 `0x14c`
  이면 32비트, `0x8664` 이면 64비트로 판별했다 (`get_bit_width`).
- **섹션 엔트로피**: 요구사항에 따라 라이브러리를 쓰지 않고 직접 구현했다.
  섹션의 원시 바이트에서 0~255 각 값의 출현 빈도로 확률 `p` 를 구한 뒤
  `-Σ p·log2(p)` 를 합산했다 (`calc_shannon_entropy`). 값의 범위는 0~8이다.
- **Import DLL/API 추출**: `pefile` 의 `DIRECTORY_ENTRY_IMPORT` 를 사용했고,
  Import 디렉터리 자체가 없는 경우(패킹된 파일에서 흔함)는 빈 목록으로
  처리했다.
- **의심 API 대조**: 추출된 API 목록과 과제 지정 의심 API 10개
  (`VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`,
  `CreateRemoteThread`, `LoadLibraryA`, `GetProcAddress`, `RegSetValueExA`,
  `InternetOpenA`, `CryptEncrypt`, `ShellExecuteA`) 의 교집합만 남겼다.

코드 전체는 `extract_features.py` 에 있으며 각 함수에 단계별 주석을 달았다.

## 3. 추출 결과 (`features.csv`)

| 파일명 | 비트수 | 섹션수 | 최대엔트로피 | 고엔트로피섹션명 | ImportDLL수 | 의심API수 | 매칭된의심API |
|---|---|---|---|---|---|---|---|
| normal_01.exe | 32 | 1 | 3.7972 | .data | 0 | 0 | |
| normal_02.exe | 32 | 1 | 8.0 | .data | 0 | 0 | |
| normal_03.exe | 32 | 3 | 4.9516 | .text | 2 | 0 | |
| packed_fixture.exe | 32 | 1 | 5.7511 | .data | 0 | 0 | |
| packed_upx_like.exe | 32 | 3 | 5.5786 | UPX1 | 1 | 2 | GetProcAddress;LoadLibraryA |
| suspicious_api.exe | 32 | 3 | 5.3294 | .text | 2 | 6 | CreateRemoteThread;GetProcAddress;LoadLibraryA;RegSetValueExA;VirtualAlloc;WriteProcessMemory |

보조로 확보한 섹션별 상세 값과 `strings` 결과(전체 Import API 목록 포함)는
아래 4장의 샘플별 근거에서 함께 인용한다.

## 4. 샘플별 판정과 근거

### 4.1 normal_01.exe — 정상

- 섹션 1개(`.data`, 8192바이트), 엔트로피 3.7972로 낮은 편.
- Import 자체가 없음(ImportDLL수 0, 의심API 0).
- `strings` 로 확인한 내용은 `"Day 1 benign text fixture."` 문장이 반복될
  뿐이며, 실행 로직이 없는 단순 텍스트 데이터 보관용 스텁 파일로 판단된다.
- **판정: 정상.**

### 4.2 normal_02.exe — 정상 (엔트로피 최댓값 오탐 주의 사례)

- 섹션 1개(`.data`, 8192바이트), **최대엔트로피 8.0** — 이론상 가능한 최댓값.
- Import 없음(ImportDLL수 0, 의심API 0).
- 얼핏 보면 "엔트로피 8.0 + Import 없음"은 패킹/암호화의 전형적 신호처럼
  보인다. 그러나 `.data` 섹션의 실제 바이트를 확인하면 `00 01 02 03 ... FE FF`
  가 32회 그대로 반복되는 **순차적 바이트 램프(ramp) 테이블**이며, 256개
  바이트 값이 정확히 32번씩 균등하게 등장한다. 이는 룩업 테이블/변환표
  성격의 정적 데이터로, 실제로 무작위이거나 압축·암호화된 데이터가 아니다.
  섀넌 엔트로피는 값의 "출현 빈도 균등성"만 측정하며 바이트의 순서(패턴)는
  전혀 보지 않기 때문에, 이런 규칙적 데이터도 엔트로피가 최댓값에 도달할
  수 있다.
- **판정: 정상.** (엔트로피만으로 패킹/악성을 판단하면 오탐이 발생하는
  대표 사례 — 상세 논의는 6장 참고)

### 4.3 normal_03.exe — 정상

- 섹션 3개(`.text`/`.rdata`/`.data`), 엔트로피는 최대 4.9516(`.text`)로
  일반적인 컴파일된 코드 수준.
- Import: `KERNEL32.dll`(CloseHandle, CreateFileW, GetLastError, ReadFile,
  WriteFile), `msvcrt.dll`(free, malloc, printf) — 표준 C 런타임과 파일
  입출력 API로만 구성되며 의심 API 목록과 전혀 겹치지 않음(의심API 0).
- `strings` 에서도 `"Configuration loaded."` 같은 평범한 로그 문자열만
  확인됨.
- **판정: 정상.**

### 4.4 packed_fixture.exe — 악성 의심

- 섹션이 단 1개(`.data`, 512바이트)뿐이며, **Import 디렉터리가 완전히
  비어 있음**(ImportDLL수 0). 정상적으로 동작하는 실행 파일이라면 최소한
  `KERNEL32.dll` 등 기본 API는 Import 되어야 하는데, 이것이 전혀 없다는
  점 자체가 강한 정황 증거다(과제 팁에서 언급된 "비어있다는 사실 자체가
  특징"에 해당).
- `strings` 결과에도 정상적인 DLL/API 이름 문자열이 전혀 없고, `c`dbfaec`,
  `WPTRVQUS`, `OHLJNIMK` 처럼 치환/난독화된 것으로 보이는 문자열 조각만
  존재한다.
- 엔트로피는 5.7511로 극단적으로 높지는 않아(순수 엔트로피 임계값만
  보면 애매한 값) 이 지표 하나만으로는 확신할 수 없지만, **Import 완전
  공백 + 판독 불가능한 문자열 패턴**을 종합하면 원본 코드/문자열이
  난독화되어 숨겨진 패킹된 실행 파일일 가능성이 높다.
- **판정: 악성 의심 (추가 언패킹·동적 분석 필요).**

### 4.5 packed_upx_like.exe — 악성 의심

- `file` 명령 자체가 이 파일을 "UPX compressed"로 인식했으며, 실제로
  섹션 이름이 `UPX0`(SizeOfRawData 0, VirtualSize 0x8000), `UPX1`
  (엔트로피 5.5786), `.rdata` 로 구성되어 UPX 패커의 전형적인 섹션 구조와
  일치한다.
- Import는 `KERNEL32.dll` 의 `LoadLibraryA`, `GetProcAddress` **단 2개뿐**
  이며 둘 다 의심 API 목록에 포함된다. 이는 패커가 실행 시점에 압축을
  해제한 뒤, 원래 필요한 API 주소를 직접 동적으로 resolve하기 위해 흔히
  남기는 "최소 Import" 패턴이다 — 원본 Import 정보를 정적 분석에서
  감추는 전형적 수법이다.
- 다만 UPX는 정상 소프트웨어도 파일 크기를 줄이기 위해 사용하는 합법적
  압축 도구이므로, 패킹 자체가 곧 악성을 의미하지는 않는다. 그러나 원본
  API 목록을 감춘 정황과 의심 API 조합이 함께 나타난 점을 근거로
  의심 등급으로 분류한다.
- **판정: 악성 의심 (패커 사용 확인, 언패킹 후 재분석 권장).**

### 4.6 suspicious_api.exe — 악성 의심 (가장 강한 정황)

- 6개 샘플 중 **의심API수가 6개로 가장 많다**: `VirtualAlloc`,
  `WriteProcessMemory`, `CreateRemoteThread`, `LoadLibraryA`,
  `GetProcAddress`, `RegSetValueExA`.
- 특히 `VirtualAlloc`(메모리 할당/실행권한 조작) + `WriteProcessMemory`
  (원격 프로세스 메모리에 코드 기록) + `CreateRemoteThread`(원격 스레드
  실행) 조합은 **프로세스 인젝션(process injection)** 의 교과서적인
  3종 API 세트다. 여기에 `OpenProcess`(대상 프로세스 핸들 획득,
  의심 목록엔 없지만 인젝션에 필수), `RegSetValueExA`/`RegCreateKeyExA`
  (레지스트리 등록 — 지속성/자동실행 확보 정황)까지 더해진다.
- `strings` 에서 `http://training.invalid/checkin` 문자열이 발견되어
  C2(명령제어 서버) 체크인을 흉내낸 것으로 보인다. 다만 Import 목록에
  `InternetOpenA` 등 네트워크 관련 API는 전혀 없어, 이 URL은 실제로
  호출되는 기능이 아니라 문자열로만 존재하는 것으로 판단된다(교육용으로
  안전하게 비활성화해 둔 것으로 추정 — `.invalid` 는 실제로 존재할 수 없는
  예약 TLD).
- 엔트로피는 최대 5.3294(`.text`)로 특별히 높지 않다. **엔트로피만 보는
  탐지 로직이라면 이 샘플은 걸러지지 않았을 것**이며, Import/API 분석이
  왜 반드시 병행되어야 하는지를 잘 보여주는 사례다.
- **판정: 악성 의심 (프로세스 인젝션 + 지속성 시도 정황, 가장 확신도 높음).**

## 5. 생성형AI 검증

### 5.1 Claude 블라인드 실험 (정상 샘플 3개, 정보 제한 조건)

방법: 스크립트로 전체 특징을 추출하기 **전에**, `file` 명령 출력과
`strings` 출력(사람이 읽을 수 있는 문자열 목록)만을 생성형AI(Claude)에게
제공하고 "각 샘플의 악성 여부와 그 근거가 된 API 이름·섹션 이름을 함께
제시하라"고 요청했다. 이후 `pefile` 기반 전체 추출 결과(3~4장)와 AI의
주장을 항목별로 대조했다.

| 샘플명 | AI가 주장한 근거 | 실제 추출 결과 | 일치 여부 |
|---|---|---|---|
| normal_01.exe | Import/API가 전혀 없고, 문자열이 사람이 읽을 수 있는 반복된 일반 텍스트뿐이라 정상으로 판단 | ImportDLL수 0, 의심API 0. 문자열은 `"Day 1 benign text fixture."` 반복으로 확인됨 | 일치 |
| normal_02.exe | Import가 없고 `.data` 섹션이 반복 패턴을 보여, 인코딩/난독화된 페이로드일 가능성이 있는 패킹된 악성코드로 의심 | `.data` 는 0x00~0xFF 순차 바이트가 32회 반복되는 정적 룩업 테이블이며 코드 섹션(.text) 자체가 없는 단순 데이터 파일. 악성 정황 없음 | **불일치 (AI 오판 — 6장 오탐 사례와 동일 건)** |
| normal_03.exe | `KERNEL32.dll`/`msvcrt.dll` 의 표준 파일 입출력·CRT API(CreateFileW, ReadFile, WriteFile, malloc, printf 등)만 사용하고 의심 API가 없어 정상 프로그램으로 판단 | Import: KERNEL32.dll, msvcrt.dll / API 8개 전부 의심 목록과 불일치, 의심API수 0 | 일치 |

**Claude가 잘못 지목한 항목**: `normal_02.exe` — 정상 데이터 테이블을
"인코딩된 페이로드"로 오판했다(엔트로피가 높고 Import가 없으면 무조건
패킹/악성이라는 성급한 일반화). 정보가 `file`/`strings` 요약뿐이라 실제
바이트 패턴(0x00~0xFF 순차 반복)을 볼 수 없었던 것이 원인으로 보인다.

### 5.2 Claude 실제 세션 결과 대조 (정상 샘플 3개, 상세 정보 조건)

방법: 수강생이 별도 채팅 세션에서 Claude에게 정상 샘플 3개(`normal_01~03.exe`)의
PE 구조(섹션, EntryPoint, Import, 섹션 특성 플래그, 문자열)를 제시하고 악성
여부 판정과 근거를 요청했다(5.1의 블라인드 조건과 달리 상세 정보가 주어진
조건). 아래는 그 답변의 핵심 주장을 `pefile` 및 원시 바이트 재검증 결과와
대조한 것이다.

| 샘플명 | Claude가 주장한 근거 | 실제 추출/검증 결과 | 일치 여부 |
|---|---|---|---|
| normal_01.exe | `.data` 섹션 1개만 존재, `.text`(코드) 없음, Import 없음, `EntryPoint=0x0`, 엔트로피 3.80(낮음), 문자열 `"Day 1 benign text fixture."` 반복 → 실행 코드가 전혀 없어 크래시하거나 아무 동작도 하지 않는 테스트용 더미 파일로 판단, 위험 없음 | `EntryPoint=0x0` 정확. `.data` 1개뿐(Import 0)도 정확. 엔트로피 3.7972(반올림 시 3.80) 일치. 문자열도 확인됨 | **일치** |
| normal_02.exe | `.data` 섹션만, Import 없음, `EntryPoint=0x0`, 엔트로피 8.00(최대), 문자열은 출력 가능 ASCII 문자표가 반복 배치된 "구조적 데이터"로 보아 실제 암호화가 아니라 높은 엔트로피 테스트용 인위적 데이터로 판단 → 정상. "엔트로피만 보면 패킹으로 오탐하기 쉬운 케이스"라고 스스로 단서를 닮 | `EntryPoint=0x0`, 엔트로피 8.0 정확. 실제 바이트는 0x00~0xFF 순차 램프이며, "반복 배치된 구조적 데이터"라는 해석도 본질적으로 부합(균등 분포이나 규칙적) | **일치** (5.1의 블라인드 실험과 달리, 이번엔 같은 엔트로피 8.0 신호를 보고도 정상으로 올바르게 판정 — 정보량 차이가 판정 정확도에 영향을 준 사례) |
| normal_03.exe | `.text`/`.rdata`/`.data` 3개 섹션, EntryPoint 정상 지정, Import(`KERNEL32.dll`: CreateFileW/ReadFile/WriteFile/CloseHandle/GetLastError, `msvcrt.dll`: printf/malloc/free), 문자열 `"Configuration loaded."`/`"Report written."`/`"C:\ProgramData\training\report.log"`/`"training build 1.0.4"` 확인, 악성 지표 API 전무 → 정상. 추가로 "`.rdata` 섹션 특성 플래그가 **쓰기 가능**(`0x40000040`)으로 설정되어 있는데, 이는 컴파일러 설정 차이일 뿐 악성 지표는 아니다"라고 언급 | `EntryPoint=0x1010`(`.text` 내부) 정확. Import 목록 정확히 일치. 문자열 4개 전부 정확한 파일 오프셋(`0x706`/`0x71c`/`0x72c`/`0x800`)에서 확인됨. **다만 `.rdata` Characteristics `0x40000040`은 "쓰기 가능"이 아니다** — `IMAGE_SCN_MEM_WRITE`(`0x80000000`) 비트가 꺼져 있으며, `pefile`의 플래그 상수로 디코딩하면 `IMAGE_SCN_MEM_READ`(`0x40000000`)+`IMAGE_SCN_CNT_INITIALIZED_DATA`(`0x40`)만 설정된 **읽기 전용** 섹션이다 | **부분 불일치 (해석 오류)** — 16진수 값 자체와 최종 판정("악성 지표 아님")은 맞았지만, 그 값을 "쓰기 가능"으로 잘못 디코딩함. 실제로는 쓰기 불가능한 읽기 전용 데이터 섹션 |

**Claude(정상 샘플 세션)가 잘못 지목한 항목**: `normal_03.exe`의 `.rdata`
섹션 특성 플래그(`0x40000040`)를 "쓰기 가능"이라고 설명했으나, 실제로는
`IMAGE_SCN_MEM_WRITE` 비트가 꺼져 있는 **읽기 전용** 섹션이다. 5.1의
`normal_02.exe` 오류(정보 부족으로 인한 성급한 일반화)와는 성격이 다르다
— 이번에는 수치 자체는 정확히 인용했지만, PE 섹션 플래그 비트의 의미를
잘못 해석한 **도메인 지식 오류**다. 다행히 이 오류가 최종 판정("악성
아님")에는 영향을 주지 않았지만, 만약 다른 샘플에서 "쓰기+실행 가능한
섹션"처럼 실제로 위험한 조합을 이런 식으로 잘못 디코딩했다면 판정 자체가
뒤집힐 수 있었다는 점에서 가볍게 넘길 문제는 아니다.

### 5.3 ChatGPT 실질의 결과 대조 (악성 의심 샘플 3개, 상세 정보 조건)

방법: 이번에는 `file`/`strings` 요약이 아니라, PE 헤더 필드(Entry Point,
ImageBase, 섹션별 VA/VirtualSize/RawSize/Characteristics, Import 디렉터리
RVA/Size, 문자열과 그 파일 오프셋)를 상세히 제공한 뒤 ChatGPT에게 악성
여부 판정과 근거를 요청했다(수강생이 실제로 수행). 아래는 ChatGPT가 제시한
핵심 주장을 `pefile` 및 원시 바이트 재검증 결과와 대조한 것이다.

| 샘플명 | ChatGPT가 주장한 근거 | 실제 추출/검증 결과 | 일치 여부 |
|---|---|---|---|
| packed_fixture.exe | `AddressOfEntryPoint=0x0`, `ImageBase=0x400000`, 섹션은 `.data`(VA 0x1000, VirtualSize 0x161, RawSize 0x200, Characteristics `0x40000040`=READ+INITIALIZED_DATA) 1개뿐이고 Import RVA/Size 모두 0 → 실행 코드가 없는 비정상 PE이며 "악성이라기보다 분석용 fixture"로 판단 | 재검증 결과 EntryPoint·ImageBase·VA·VirtualSize·RawSize·Characteristics·Import RVA/Size **전부 정확히 일치**. `0x40000040`의 플래그 해석(READ+INITIALIZED_DATA)도 정확 | **일치** (수치 인용과 판정 논리 모두 타당) |
| packed_upx_like.exe | 섹션 `UPX0`(VA 0x1000, VirtualSize 0x8000, RawSize 0, Characteristics `0xC0000080`)/`UPX1`/`.rdata`, 파일 내 `UPX!` 매직 문자열 존재, `EntryPoint=0x9010`(UPX1 섹션 내부), Import는 `KERNEL32.dll`의 `LoadLibraryA`/`GetProcAddress` 뿐 → "패킹된 실행 파일, 악성 증거는 없음"으로 판단 | 전 항목 재검증 결과 **정확히 일치**. `UPX!` 문자열은 파일 오프셋 `0x470`에서 실제 확인됨. `EntryPoint 0x9010`은 `UPX1`의 VA 범위(`0x9000`~`0x914E`) 내부가 맞음 | **일치** |
| suspicious_api.exe | `EntryPoint=0x1010`(`.text` 내부), `.text` Characteristics=`0xE0000020`, `.rdata`가 파일 오프셋 `0x600`~`0x800`에 위치하고 그 안에 `VirtualAlloc`(`0x69C`)/`WriteProcessMemory`(`0x6AC`)/`CreateRemoteThread`(`0x6C2`)/`OpenProcess`(`0x6D8`)/`LoadLibraryA`(`0x6E6`)/`GetProcAddress`(`0x6F6`)/`RegSetValueExA`(`0x716`)/`RegCreateKeyExA`(`0x728`)/URL 문자열(`0x738`)/레지스트리 Run 키 문자열 `"Software\Microsoft\Windows\CurrentVersion\Run"`(`0x758`)이 순서대로 존재. `OpenProcess`+`WriteProcessMemory`+`CreateRemoteThread`(프로세스 인젝션) + Run 키(지속성) + URL 조합으로 "악성 의심 매우 높음" 판정. 단, `VirtualAllocEx`가 아닌 `VirtualAlloc`이 Import된 점을 지적하며 "Import만으로 실행 여부를 단정할 수 없다"는 단서를 달음 | 문자열 오프셋 9개(`0x69C`~`0x758`) **전부 바이트 단위로 정확히 일치**. Run 키 문자열도 `0x758`에서 실제 확인됨. `.text` Characteristics도 정확. `VirtualAllocEx` 미포함(`VirtualAlloc`만 Import)이라는 지적도 정확 | **일치** (수치·문자열 인용에 오류 없음, "단정 금지" 단서도 적절) |

**ChatGPT가 잘못 지목한 항목**: 없음. 세 샘플 모두 Entry Point, 섹션
Characteristics, Import 목록, 심지어 문자열의 파일 오프셋까지 재검증
결과와 정확히 일치했다.

### 5.4 세 차례 AI 검증의 종합 비교 — 얻은 핵심 교훈

이번 과제에서는 서로 다른 조건의 AI 세션 3개를 비교할 수 있었다.

| 세션 | 대상 | 정보 조건 | 발견된 오류 | 오류의 성격 |
|---|---|---|---|---|
| 5.1 Claude 블라인드 | 정상 3개 | `file`/`strings` 요약만 | `normal_02.exe` 완전 오판 | **정보 부족 → 성급한 일반화** (엔트로피 높음+Import 없음=무조건 악성) |
| 5.2 Claude 실제 세션 | 정상 3개 | PE 헤더·플래그·문자열 상세 제공 | `normal_03.exe` 플래그 해석 오류 | **정보는 충분했으나 도메인 지식 오류** (WRITE 비트 유무를 잘못 디코딩) |
| 5.3 ChatGPT 실제 세션 | 의심 3개 | PE 헤더·오프셋 상세 제공 | 없음 | 해당 없음 |

여기서 확인되는 것은 **정보를 충분히 주는 것만으로는 오류가 사라지지
않는다**는 점이다. 5.1의 오류는 "정보가 부족해서" 생겼지만, 5.2의 오류는
정보가 상세히 주어졌는데도 **비트 플래그를 잘못 해석**하는, 종류가 다른
실수였다. 반면 5.3(ChatGPT)은 비슷한 수준의 상세 정보를 받고도 오류가
없었다 — 즉 오류 발생 여부는 정보량만이 아니라 AI가 그 정보를 다루는
방식에도 좌우된다는 뜻이다.

따라서 생성형AI 검증에서는 최소 두 층위를 모두 확인해야 한다.

1. **사실 확인**: AI가 언급한 API 이름·섹션 이름·문자열·수치가 실제로
   존재하는가? (5.1의 오류 유형 — 지어낸 근거를 걸러낸다)
2. **해석 확인**: 존재하는 수치를 AI가 올바르게 해석했는가? (5.2의 오류
   유형 — 값은 맞지만 의미를 잘못 읽은 것을 걸러낸다)

두 층위 중 하나만 확인하면 놓치는 오류가 생긴다. 5.2의 사례가 정확히
그렇다 — `0x40000040`이라는 숫자 자체는 실제 값과 정확히 일치했으므로
"숫자가 진짜 있는지"만 확인했다면 이 오류를 잡아내지 못했을 것이다.
이 오류를 잡아낸 것은 그 숫자를 `pefile`의 공식 플래그 상수로 직접
재디코딩해본 것이었다. 결국 "생성형AI가 내놓은 해석을 원본 추출 결과와
대조해 사실 여부를 가려낸다"는 이번 과제의 목표는, 언급된 항목의 존재
여부뿐 아니라 그 항목에 대한 **해석**까지 원본 데이터로 재현해서
검증해야 완성된다는 것을 세 실험이 함께 보여준다.

## 6. 오탐 가능성 논의

`normal_02.exe` 는 이번 6개 샘플 중 **가장 중요한 오탐(false positive)
사례**다.

- 최대엔트로피가 이론적 상한인 8.0에 도달했고, Import DLL이 0개(패킹된
  샘플들과 동일한 패턴)라는 두 지표만 보면 "패킹/암호화된 악성코드"라는
  결론을 내리기 쉽다. 실제로 5장의 AI 검증에서도 이 샘플에 대해서만
  AI가 완전히 틀린 판정을 내렸다.
- 그러나 실제 데이터는 `0x00`부터 `0xFF`까지 256개의 값이 정확히 32회씩
  등장하는 **순차적 램프 테이블**이다. 섀넌 엔트로피는 "각 값이 얼마나
  균등하게 등장하는가"만 측정하고 바이트가 어떤 **순서**로 나열되어
  있는지는 전혀 고려하지 않기 때문에, 완전히 규칙적인 데이터(정렬된
  테이블, 사인파 룩업 테이블, 폰트/문자 변환표 등)도 무작위 데이터나
  압축·암호화된 데이터와 동일하게 최댓값에 도달할 수 있다.
- Import가 없는 이유도 실제로는 이 파일이 순수 데이터 블롭(코드 로직이
  없는 리소스/테이블 저장용 스텁)이기 때문이지, 원본 Import 정보를
  감추기 위한 패킹 때문이 아니다. 즉 "Import 없음"이라는 동일한 신호도
  원인이 전혀 다를 수 있다.
- **시사점**: 엔트로피와 Import 유무는 훌륭한 1차 스크리닝 지표이지만,
  단독으로는 오탐을 일으키기 쉽다. 실전에서는 (1) 해당 섹션이 코드
  섹션(`.text`, 실행 가능 속성)인지 데이터 섹션인지, (2) 바이트열에
  `normal_02.exe` 처럼 뚜렷한 반복/순차 패턴이 있는지(자기상관·반복
  주기 검사), (3) 파일 전체 크기 대비 의미 있는 코드가 존재하는지 등을
  함께 봐야 하며, 정적 특징만으로 애매한 경우 문자열/디스어셈블/동적
  분석 등 추가 검증이 필요하다.

반대로 `packed_fixture.exe` 는 엔트로피가 5.7511로 "매우 높다"고 보기엔
애매한 값이었다. 엔트로피 임계값(예: 7.0 이상만 패킹으로 간주)만 적용하는
규칙이었다면 이 샘플은 정상으로 오분류(false negative)될 수 있었다.
Import 테이블이 완전히 비어 있다는 별도 지표를 함께 봤기 때문에 의심
등급으로 정확히 분류할 수 있었다 — 단일 지표가 아닌 **복수 지표의
교차 검증**이 필요함을 보여주는 또 다른 사례다.

## 7. 결론

| 샘플 | 최종 판정 | 핵심 근거 |
|---|---|---|
| normal_01.exe | 정상 | Import 없음 + 낮은 엔트로피 + 반복된 일반 텍스트 |
| normal_02.exe | 정상 | 엔트로피 8.0은 순차 룩업 테이블에 의한 것(오탐 사례) |
| normal_03.exe | 정상 | 표준 CRT/파일 API만 사용, 의심 API 0개 |
| packed_fixture.exe | 악성 의심 | Import 완전 공백 + 판독 불가 문자열 패턴 |
| packed_upx_like.exe | 악성 의심 | UPX 패커 시그니처 + LoadLibraryA/GetProcAddress만 Import |
| suspicious_api.exe | 악성 의심 | 프로세스 인젝션 3종 API + 레지스트리 등록 정황, 의심API 6개(최다) |

생성형AI 검증은 세 조건으로 나눠 진행했다(5장). **정보가 제한된 조건**
(Claude 블라인드, `file`/`strings` 요약만 제공, 5.1절)에서는 정상 샘플
3개 중 1개(`normal_02.exe`)를 완전히 오판했다 — 정상적인 룩업 테이블을
"인코딩된 페이로드"로 잘못 지목한, **정보 부족에 의한 성급한 일반화**
사례다. **정보가 상세한 조건**에서는 두 세션을 비교할 수 있었는데,
Claude 실제 세션(정상 샘플 3개, 5.2절)은 `normal_03.exe`의 섹션 특성
플래그(`0x40000040`)를 "쓰기 가능"으로 잘못 해석했다 — 수치 인용은
정확했지만 그 값의 **의미를 잘못 디코딩한 해석 오류**였다. 반면 ChatGPT
실제 세션(악성 의심 샘플 3개, 5.3절)은 API·섹션·Entry Point·문자열
오프셋까지 오류 없이 정확했다.

이는 생성형AI의 결론을 **정보의 양과 무관하게, 그리고 오류 유형과
무관하게 무조건 재검증해야 하는 이유**를 잘 보여준다 — 정보가 부족하면
AI는 실제로 존재하지 않는 근거를 자신 있게 만들어내고(사실 오류), 정보가
충분해도 그 수치의 의미를 잘못 해석할 수 있다(해석 오류). 두 오류 유형
모두 "AI가 언급한 것이 실제로 존재하는가"만 확인해서는 잡아낼 수 없는
경우가 있으며(특히 해석 오류는 숫자 자체가 맞기 때문에 더 찾기 어렵다),
반드시 원본 추출 결과·플래그 상수와 직접 대조해야 발견할 수 있었다.
결국 생성형AI는 정적 분석을 돕는 보조 도구일 뿐, 최종 판단의 근거는
항상 `pefile` 기반 원본 추출 결과가 되어야 한다.
