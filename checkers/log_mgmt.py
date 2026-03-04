#patch_mgmt w-40 ~ w-43
import subprocess
import json
import os

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

def check_w40():
    """W-40: 정책에 따른 시스템 로깅 설정"""
    result = {"id": "W-40", "title": "정책에 따른 시스템 로깅 설정", "status": "양호", "details": []}
    # 주요 감사 정책(로그온, 권한 사용 등) 확인
    audit_policy = subprocess.run("auditpol /get /category:*", capture_output=True, text=True, shell=True)
    
    # '성공 및 실패' 기록 여부 확인 (예시: 로그온 이벤트)
    if "성공 및 실패" not in audit_policy.stdout and "Success and Failure" not in audit_policy.stdout:
        result["status"] = "취약"
        result["details"].append("주요 감사 정책(로그온/로그오프 등)이 '성공 및 실패'를 모두 기록하도록 설정되지 않았습니다.")
    else:
        result["details"].append("감사 정책이 권고 기준에 따라 설정되어 있습니다.")
    return result

def check_w41():
    """W-41: NTP 및 시각 동기화 설정"""
    result = {"id": "W-41", "title": "NTP 및 시각 동기화 설정", "status": "양호", "details": []}
    # 시각 동기화 소스 확인
    time_src = run_ps("w32tm /query /source")
    
    if "Local CMOS Clock" in str(time_src) or "Free-running System Clock" in str(time_src):
        result["status"] = "취약"
        result["details"].append("외부 NTP 서버와 동기화되지 않고 로컬 시계를 사용 중입니다.")
    else:
        result["details"].append(f"동기화 서버: {time_src}")
    return result

def check_w42():
    """W-42: 이벤트 로그 관리 설정 (용량 및 보관 기간)"""
    result = {"id": "W-42", "title": "이벤트 로그 관리 설정", "status": "양호", "details": []}
    # Security 로그 설정 확인
    log_info = run_ps("Get-EventLog -List | Where-Object { $_.Log -eq 'Security' }")
    
    if log_info:
        max_size_kb = log_info.get('MaximumKilobytes', 0)
        # 10,240KB 미만인지 확인
        if max_size_kb < 10240:
            result["status"] = "취약"
            result["details"].append(f"최대 로그 크기가 {max_size_kb}KB로 설정되어 있습니다. (10,240KB 이상 권고)")
        else:
            result["details"].append(f"최대 로그 크기가 {max_size_kb}KB로 적절합니다.")
    return result

def check_w43():
    """W-43: 이벤트 로그 파일 접근 통제 설정"""
    result = {"id": "W-43", "title": "이벤트 로그 파일 접근 통제 설정", "status": "양호", "details": []}
    # 윈도우 이벤트 로그 디렉토리 권한 점검
    log_path = os.environ.get('SystemRoot') + "\\System32\\winevt\\Logs"
    acl = run_ps(f"Get-Acl '{log_path}' | Select-Object -ExpandProperty Access")
    
    if acl:
        if isinstance(acl, dict): acl = [acl]
        for entry in acl:
            if entry.get('IdentityReference') == 'Everyone':
                result["status"] = "취약"
                result["details"].append("로그 디렉토리 권한에 Everyone이 포함되어 있습니다.")
                break
    
    if not result["details"]:
        result["details"].append("로그 디렉토리에 Everyone 권한이 포함되어 있지 않습니다.")
    return result