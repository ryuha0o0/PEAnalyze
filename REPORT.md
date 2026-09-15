# PE 정적 특징 추출기 작성과 생성형AI 분석 결과 검증 — 보고서

## 1. 개요

강사가 배포한 PE 샘플 6개(정상 3 / 악성 의심 3)를 대상으로 `extract_features.py`
스크립트를 작성해 정적 특징을 추출하고, 그 결과를 `features.csv` 로 저장했다.
이어서 생성형AI에게 각 샘플의 악성 여부 판정을 요청한 뒤, AI가 근거로 제시한
API·섹션·수치가 실제 추출 결과와 일치하는지 대조했다. 검증은 두 가지 방식으로
진행했다.

1. **Claude 블라인드 실험** (정상 샘플 3개 대상, 5.1절): `file`/`strings`
   출력처럼 제한된 정보만 준 뒤 판정을 요청 — AI가 정보가 부족할 때 어떤
   식으로 오판하는지 관찰.
2. **ChatGPT 실질의** (악성 의심 샘플 3개 대상, 5.2절): PE 헤더 필드(Entry
   Point, 섹션별 VA/크기/Characteristics, Import, 문자열과 파일 오프셋)를
   상세히 제공한 뒤 판정을 요청 — 정보가 충분할 때의 인용 정확도를 검증.

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

### 5.2 ChatGPT 실질의 결과 대조 (악성 의심 샘플 3개, 상세 정보 조건)

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

### 5.3 두 실험의 대비 — AI 검증에서 얻은 핵심 교훈

같은 생성형AI라도 **입력으로 주어지는 정보의 구체성에 따라 인용 정확도가
크게 달라진다.**

- 5.1(Claude, `file`/`strings` 요약 정보만 제공): `normal_02.exe`에서
  오판 발생 — 정보가 부족해 실제 바이트 패턴을 보지 못하고 "엔트로피 높음
  + Import 없음 = 악성"이라는 얕은 규칙으로 넘겨짚었다.
- 5.2(ChatGPT, PE 헤더 필드와 파일 오프셋까지 상세 제공): 세 샘플 모두
  오류 없이 정확 — 원본 데이터가 충분하니 근거를 지어낼 필요가 없었다.

다만 이 결과가 "정보를 충분히 주면 AI 검증 절차를 생략해도 된다"는 뜻은
아니다. 5.2에서도 **모든 주장을 실제로 재검증했고**(오프셋 하나하나까지
`pefile`/원시 바이트로 대조), 검증을 생략했다면 ChatGPT의 답변이 우연히
정확했는지 실제로 확인된 것인지 구분할 수 없었을 것이다. 즉 "AI에게 더
좋은 정보를 줄수록 신뢰도는 올라가지만, 검증 자체를 건너뛸 근거는 되지
않는다"는 것이 이번 과제의 핵심 교훈이다.

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

생성형AI 검증은 두 조건으로 나눠 진행했다. **정보가 제한된 조건**
(Claude, `file`/`strings` 요약만 제공, 5.1절)에서는 정상 샘플 3개 중
1개(`normal_02.exe`)를 오판했다 — 정상적인 룩업 테이블을 "인코딩된
페이로드"로 잘못 지목한 사례다. 반면 **정보가 상세한 조건**(ChatGPT,
PE 헤더 필드와 문자열 오프셋까지 제공, 5.2절)에서는 악성 의심 샘플 3개
전부 API·섹션·Entry Point·문자열 오프셋까지 오류 없이 정확했다.

이는 생성형AI의 결론을 **주어진 정보의 양과 무관하게 무조건 재검증해야
하는 이유**를 잘 보여준다 — 정보가 부족하면 AI는 "그럴듯한 패턴"(엔트로피가
높으면 악성, 패킹된 것처럼 보이면 UPX 섹션명을 가정)에 기반해 실제로
존재하지 않는 근거를 자신 있게 만들어내는 경향이 있었고, 정보가 충분해도
그 답이 "우연히 맞았는지 실제로 검증됐는지"는 원본 추출 결과와 대조하지
않고서는 알 수 없다. 결국 생성형AI는 정적 분석을 돕는 보조 도구일 뿐,
최종 판단의 근거는 항상 `pefile` 기반 원본 추출 결과가 되어야 한다.
