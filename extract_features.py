"""
PE 정적 특징 추출기 (PE Static Feature Extractor)

목적:
    강사가 배포한 PE 샘플들을 대상으로 다음을 수행한다.
      1) MZ/PE 시그니처 확인 및 32/64비트 판별
      2) 섹션별 이름/크기/엔트로피 계산 (엔트로피는 라이브러리 없이 직접 구현)
      3) Import DLL 목록과 API 목록을 추출하고, 지정된 의심 API 목록과 대조
      4) 위 결과를 features.csv 로 저장 (샘플 1개당 1행)

주의:
    악성으로 의심되는 샘플은 절대 실행하지 않는다. 이 스크립트는 파일을
    바이트 단위로 읽거나 pefile 로 "파싱"만 할 뿐, 어떤 샘플도 실행(exec,
    subprocess 등)하지 않는다. 반드시 격리된 환경에서만 사용할 것.

사용법:
    python extract_features.py <샘플_디렉터리> <출력_csv_경로>
"""

import os
import sys
import csv
import math
import glob
import pefile

# ---------------------------------------------------------------------------
# 과제에서 지정한 "의심 API" 목록.
# 이 API들은 각각 아래와 같은 이유로 악성코드가 자주 사용하는 기능과 연관된다.
#   - VirtualAlloc/VirtualProtect : 메모리 실행 권한 조작 (셸코드 실행, 언패킹)
#   - WriteProcessMemory/CreateRemoteThread : 프로세스 인젝션
#   - LoadLibraryA/GetProcAddress : 런타임 동적 API 로딩 (정적 분석 우회)
#   - RegSetValueExA : 레지스트리 변경 (지속성/부팅 시 자동 실행 등록)
#   - InternetOpenA : 네트워크 통신 (C2 연결, 정보 유출)
#   - CryptEncrypt : 암호화 (랜섬웨어, 통신 난독화)
#   - ShellExecuteA : 외부 프로그램/명령 실행
# ---------------------------------------------------------------------------
SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "LoadLibraryA",
    "GetProcAddress",
    "RegSetValueExA",
    "InternetOpenA",
    "CryptEncrypt",
    "ShellExecuteA",
}


def calc_shannon_entropy(data: bytes) -> float:
    """섀넌(Shannon) 엔트로피를 외부 라이브러리 없이 직접 계산한다.

    계산 방법:
        1. 데이터에 등장하는 바이트 값(0~255) 각각의 출현 횟수를 센다.
        2. 각 값의 등장 확률 p = (해당 값의 개수) / (전체 바이트 수) 를 구한다.
        3. -Σ p * log2(p) 를 모든 값에 대해 합산한다 (p=0인 값은 제외).
    값의 범위는 이론상 0(모든 바이트가 동일)~8(완전 균등 분포, 무작위/압축/암호화 데이터).
    """
    if not data:
        return 0.0

    # 0~255 각 바이트 값의 출현 횟수를 세기 위한 빈도표
    freq = [0] * 256
    for b in data:
        freq[b] += 1

    length = len(data)
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue  # 등장하지 않은 값은 확률이 0이므로 log2(0) 계산을 피한다
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def check_mz_pe_signature(filepath: str):
    """파일을 직접 바이트 단위로 읽어 MZ 시그니처와 PE 시그니처를 확인한다.
    pefile 로 파싱하기 전에, 이 파일이 실제로 PE 포맷인지 원시 바이트
    레벨에서 먼저 검증하기 위한 함수이다.

    반환값: (is_valid: bool, e_lfanew: int)
    """
    with open(filepath, "rb") as f:
        header = f.read(0x40)  # DOS 헤더(64바이트)만 읽으면 e_lfanew 위치까지 확보 가능

    if len(header) < 0x40 or header[:2] != b"MZ":
        # 파일 앞 2바이트가 'MZ'(0x4D, 0x5A)가 아니면 DOS/PE 실행파일이 아님
        return False, -1

    # DOS 헤더의 0x3C 오프셋에 PE 헤더 시작 위치(e_lfanew)가 4바이트 리틀엔디안으로 저장됨
    e_lfanew = int.from_bytes(header[0x3C:0x40], byteorder="little")

    with open(filepath, "rb") as f:
        f.seek(e_lfanew)
        pe_sig = f.read(4)

    # PE 헤더 시작 지점에 'PE\x00\x00' 시그니처가 있어야 정상적인 PE 파일
    is_valid = pe_sig == b"PE\x00\x00"
    return is_valid, e_lfanew


def get_bit_width(pe: pefile.PE) -> int:
    """IMAGE_FILE_HEADER.Machine 값을 보고 32비트/64비트를 판별한다.
    Optional Header 의 Magic 값(0x10b/0x20b)으로도 판별 가능하지만,
    Machine 필드가 아키텍처를 더 직접적으로 나타내므로 이를 사용한다.
        0x014c = IMAGE_FILE_MACHINE_I386  -> 32비트
        0x8664 = IMAGE_FILE_MACHINE_AMD64 -> 64비트
    """
    machine = pe.FILE_HEADER.Machine
    if machine == 0x8664:
        return 64
    if machine == 0x014C:
        return 32
    return 0  # x86/x64 가 아닌 알 수 없는 아키텍처(과제 범위 밖)


def extract_sections(pe: pefile.PE):
    """섹션별 이름/크기(SizeOfRawData)/엔트로피를 리스트[dict]로 반환한다.
    엔트로피는 위에서 직접 구현한 calc_shannon_entropy() 를 사용한다
    (pefile 에도 자체 엔트로피 계산 기능이 있으나 과제 요구사항에 따라 사용하지 않음).
    """
    sections = []
    for section in pe.sections:
        # 섹션 이름은 8바이트 고정 길이이며 남는 부분은 NULL(0x00)로 채워지므로 제거
        name = section.Name.rstrip(b"\x00").decode(errors="replace")
        size = section.SizeOfRawData

        # 섹션의 실제 원시 데이터를 읽어와 엔트로피를 계산한다.
        raw_data = section.get_data()
        entropy = calc_shannon_entropy(raw_data)

        sections.append({"name": name, "size": size, "entropy": entropy})
    return sections


def extract_imports(pe: pefile.PE):
    """Import DLL 목록과 API(함수) 목록을 추출한다.

    패킹된(packed) 샘플은 원본 Import 정보가 압축/암호화되어 숨겨져 있어
    Import 테이블이 비어있거나 극소수만 남아있는 경우가 많다. 이 함수는 그런
    경우 단순히 빈 리스트를 반환하며, "Import가 거의 없다"는 사실 자체를
    호출부에서 특징으로 활용한다.
    """
    dlls = []
    apis = []

    # DIRECTORY_ENTRY_IMPORT 속성 자체가 없으면 Import 디렉터리가 비어있는 것
    if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        return dlls, apis

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = entry.dll.decode(errors="replace") if entry.dll else "UNKNOWN"
        dlls.append(dll_name)
        for imp in entry.imports:
            if imp.name:  # ordinal(번호)로만 import되어 이름이 없는 경우는 제외
                apis.append(imp.name.decode(errors="replace"))

    return dlls, apis


def analyze_sample(filepath: str) -> dict:
    """샘플 1개(.exe)를 분석하여 features.csv 의 한 행에 해당하는 값을 만든다."""
    filename = os.path.basename(filepath)

    # 1단계: MZ/PE 시그니처 확인 (원시 바이트 레벨 검증)
    is_valid, _ = check_mz_pe_signature(filepath)
    if not is_valid:
        raise ValueError(f"{filename}: MZ/PE 시그니처가 올바르지 않음 (PE 파일 아님)")

    # 2단계: pefile 로 헤더 구조체 파싱 (섹션/Import 파싱에만 사용, 엔트로피 계산에는 미사용)
    pe = pefile.PE(filepath, fast_load=False)
    try:
        bits = get_bit_width(pe)
        sections = extract_sections(pe)
        dlls, apis = extract_imports(pe)

        # 3단계: 섹션 중 엔트로피가 가장 높은 섹션을 찾는다.
        #   -> 코드/데이터 섹션치고 지나치게 높은 엔트로피(예: 7.5 이상)는
        #      압축(packing) 또는 암호화의 강력한 정황 증거가 된다.
        if sections:
            max_section = max(sections, key=lambda s: s["entropy"])
            max_entropy = round(max_section["entropy"], 4)
            max_entropy_section_name = max_section["name"]
        else:
            max_entropy = 0.0
            max_entropy_section_name = ""

        # 4단계: 실제 import 된 API 이름과 의심 API 목록의 교집합만 남긴다.
        matched_apis = sorted(set(apis) & SUSPICIOUS_APIS)

        return {
            "파일명": filename,
            "비트수": bits,
            "섹션수": len(sections),
            "최대엔트로피": max_entropy,
            "고엔트로피섹션명": max_entropy_section_name,
            "ImportDLL수": len(set(dlls)),
            "의심API수": len(matched_apis),
            "매칭된의심API": ";".join(matched_apis),
            # CSV 컬럼에는 없지만 보고서 작성을 위한 상세 정보(내부용)
            "_sections_detail": sections,
            "_all_apis": sorted(set(apis)),
            "_all_dlls": sorted(set(dlls)),
        }
    finally:
        pe.close()  # 파일 핸들을 명시적으로 닫는다


# 인자 없이 실행할 경우 사용할 기본 경로. 강사 배포 샘플 6개가 저장소의
# PE_6/ 디렉터리에 포함되어 있으므로, 별도 인자 없이 바로 분석할 수 있도록 한다.
DEFAULT_SAMPLE_DIR = "PE_6"
DEFAULT_OUTPUT_CSV = "features.csv"


def main():
    # 인자를 주면 그 경로를 쓰고, 생략하면 기본값(PE_6 -> features.csv)을 사용한다.
    sample_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SAMPLE_DIR
    output_csv = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUTPUT_CSV

    # 과제 요구사항에 명시된 컬럼 순서 그대로 사용
    columns = [
        "파일명", "비트수", "섹션수", "최대엔트로피",
        "고엔트로피섹션명", "ImportDLL수", "의심API수", "매칭된의심API",
    ]

    exe_files = sorted(glob.glob(os.path.join(sample_dir, "*.exe")))
    if not exe_files:
        print(f"'{sample_dir}' 안에서 .exe 파일을 찾지 못했습니다.")
        sys.exit(1)

    rows = []
    for filepath in exe_files:
        try:
            result = analyze_sample(filepath)
            rows.append(result)
            print(f"[OK]   {result['파일명']}: {result['비트수']}bit, "
                  f"섹션 {result['섹션수']}개, 최대엔트로피 {result['최대엔트로피']}"
                  f"({result['고엔트로피섹션명']}), 의심API {result['의심API수']}개")
        except Exception as e:
            print(f"[FAIL] {os.path.basename(filepath)}: {e}")

    # utf-8-sig 로 저장해야 엑셀에서 한글 컬럼명이 깨지지 않는다
    with open(output_csv, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"\n총 {len(rows)}개 샘플 분석 완료 -> {output_csv}")


if __name__ == "__main__":
    main()
