#patch_mgmt w-38 ~ w-39
import subprocess
import json

def run_ps(cmd):
    """파워쉘 명령 실행 후 JSON 또는 문자열 반환"""
    full_cmd = f"powershell -Command \"{cmd} | ConvertTo-Json\""
    proc = subprocess.run(full_cmd, capture_output=True, text=True, shell=True)
    if proc.stdout.strip():
        try:
            return json.loads(proc.stdout)
        except:
            return proc.stdout.strip()
    return None

def check_w38():
    """W-38: 주기적 보안 패치 및 벤더 권고사항 적용"""
    result = {"id": "W-38", "title": "주기적 보안 패치 및 벤더 권고사항 적용", "status": "점검필요", "details": []}
    # 최근 90일 이내의 패치 내역 확인
    patches = run_ps("Get-HotFix | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-90) }")
    
    if patches:
        count = len(patches) if isinstance(patches, list) else 1
        result["status"] = "양호"
        result["details"].append(f"최근 90일 이내에 {count}건의 보안 패치가 설치되었습니다.")
    else:
        result["status"] = "취약"
        result["details"].append("최근 90일 이내에 설치된 보안 패치 내역이 없습니다. 주기적 패치 여부를 확인하십시오.")
    return result

def check_w39():
    """W-39: 백신 프로그램 업데이트"""
    result = {"id": "W-39", "title": "백신 프로그램 업데이트", "status": "양호", "details": []}
    # Windows Defender 상태 확인
    defender = run_ps("Get-MpComputerStatus | Select-Object AntivirusSignatureAge, AntivirusEnabled")
    
    if defender:
        if defender.get('AntivirusEnabled') is False:
            result["status"] = "취약"
            result["details"].append("백신 프로그램(Windows Defender)이 비활성화되어 있습니다.")
        elif defender.get('AntivirusSignatureAge', 0) > 7:
            result["status"] = "취약"
            result["details"].append(f"백신 업데이트가 {defender.get('AntivirusSignatureAge')}일 전의 것입니다. (7일 이내 권고)")
        else:
            result["details"].append("백신 프로그램이 활성화되어 있으며 최신 상태를 유지하고 있습니다.")
    else:
        result["status"] = "점검필요"
        result["details"].append("Windows Defender 정보를 가져올 수 없습니다. 타사 백신 사용 여부를 확인하십시오.")
    return result