import subprocess
import json
import re

def run_ps(cmd):
    """파워쉘 명령 실행 후 JSON 반환"""
    full_cmd = f"powershell -Command \"{cmd} | ConvertTo-Json\""
    proc = subprocess.run(full_cmd, capture_output=True, text=True, shell=True)
    if proc.stdout.strip():
        try:
            return json.loads(proc.stdout)
        except:
            return proc.stdout.strip()
    return None

# 진단 시작(W-01~W-14)
def check_w01():
    """W-01: Administrator 계정명 및 패스워드 정책 점검"""
    result = {"id": "W-01", "title": "Administrator 계정 이름 변경", "status": "양호", "details": []}
    
    # 1. 관리자 이름 체크
    ps_cmd = "powershell -Command \"Get-LocalUser | Where-Object {$_.SID -like 'S-1-5-*-500'} | Select-Object Name | ConvertTo-Json\""
    raw = subprocess.run(ps_cmd, capture_output=True, text=True, shell=True)
    
    if raw.stdout:
        name = json.loads(raw.stdout).get("Name", "")
        if name.lower() == "administrator":
            result["status"] = "취약"
            result["details"].append(f"관리자 계정명('{name}')이 변경되지 않음")
    
    return result

def check_w02():
    """W-02: Guest 계정 비활성화"""
    result = {"id": "W-02", "title": "Guest 계정 비활성화", "status": "양호", "details": []}
    # SID S-1-5-501은 기본 Guest 계정입니다.
    data = run_ps("Get-LocalUser | Where-Object {$_.SID -like 'S-1-5-*-501'} | Select-Object Name, Enabled")
    
    if data:
        if data.get("Enabled") is True:
            result["status"] = "취약"
            result["details"].append(f"Guest 계정({data.get('Name')})이 활성화되어 있습니다.")
        else:
            result["details"].append("Guest 계정이 비활성화 상태입니다.")
    return result

def check_w03():
    """W-03: 불필요한 계정 제거 (현황 출력 및 관리자 확인 유도)"""
    result = {"id": "W-03", "title": "불필요한 계정 제거", "status": "점검필요", "details": []}
    data = run_ps("Get-LocalUser | Select-Object Name, Description, LastLogon")
    
    if isinstance(data, list):
        names = [u.get("Name") for u in data]
        result["details"].append(f"현재 시스템 계정 리스트: {', '.join(names)}")
        result["details"].append("퇴직/휴직자 등 불필요한 계정이 있는지 수동 확인이 필요합니다.")
    return result

def check_w04():
    """W-04: 계정 잠금 임계값 설정 (5회 이하 양호)"""
    result = {"id": "W-04", "title": "계정 잠금 임계값 설정", "status": "양호", "details": []}
    net_accounts = subprocess.run("net accounts", capture_output=True, text=True, shell=True, encoding='cp949').stdout
    
    threshold = 0
    found = False
    for line in net_accounts.splitlines():
        if "계정 잠금 임계값" in line or "Lockout threshold" in line:
            threshold = int(re.sub(r'[^0-9]', '', line))
            found = True
            break
    
    if not found or threshold == 0 or threshold > 5:
        result["status"] = "취약"
        result["details"].append(f"계정 잠금 임계값이 {threshold}회로 설정되어 있습니다. (기준: 1~5회)")
    else:
        result["details"].append(f"계정 잠금 임계값이 {threshold}회로 적절합니다.")
    return result

def check_w05():
    """W-05: 해독 가능한 암호화를 사용하여 암호 저장 해제"""
    result = {"id": "W-05", "title": "해독 가능한 암호화 사용하여 암호 저장 해제", "status": "양호", "details": []}
    # 보안 정책 값 확인 (secedit 등 활용 가능하나 레지스트리가 가장 확실함)
    reg_cmd = 'reg query "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\RemoteAccess\\Parameters" /v "AllowClearTextPassword"'
    proc = subprocess.run(reg_cmd, capture_output=True, text=True, shell=True)
    
    if "0x1" in proc.stdout:
        result["status"] = "취약"
        result["details"].append("해독 가능한 암호화 저장 정책이 활성화되어 있을 가능성이 있습니다.")
    else:
        result["details"].append("해독 가능한 암호화 저장 정책이 비활성화되어 있습니다.")
    return result

def check_w06():
    """W-06: 관리자 그룹에 최소한의 사용자 포함"""
    result = {"id": "W-06", "title": "관리자 그룹에 최소한의 사용자 포함", "status": "양호", "details": []}
    # Administrators 그룹 구성원 확인
    ps_cmd = "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name | ConvertTo-Json"
    data = run_ps("Get-LocalGroupMember -Group 'Administrators' | Select-Object Name")
    
    members = []
    if isinstance(data, list):
        members = [m.get("Name") for m in data]
    elif isinstance(data, dict):
        members = [data.get("Name")]

    if len(members) > 1:
        result["status"] = "취약"
        result["details"].append(f"관리자 그룹 인원이 {len(members)}명입니다: {', '.join(members)}")
        result["details"].append("불필요한 계정은 제거 권고합니다.")
    else:
        result["details"].append(f"관리자 그룹 인원이 {len(members)}명으로 적절합니다.")
    return result

def check_w07():
    """W-07: Everyone 사용 권한을 익명 사용자에 적용"""
    result = {"id": "W-07", "title": "Everyone 사용 권한을 익명 사용자에 적용", "status": "양호", "details": []}
    # 레지스트리 값 확인 (0: 양호, 1: 취약)
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'everyoneincludesanonymous'")
    
    val = data.get('everyoneincludesanonymous') if isinstance(data, dict) else None
    if val == 1:
        result["status"] = "취약"
        result["details"].append("정책이 '사용(1)'으로 설정되어 익명 사용자가 Everyone 권한을 가집니다.")
    else:
        result["details"].append("정책이 '사용 안 함(0)'으로 설정되어 있습니다.")
    return result

def check_w08():
    """W-08: 계정 잠금 기간 설정 (60분 이상 양호)"""
    result = {"id": "W-08", "title": "계정 잠금 기간 설정", "status": "양호", "details": []}
    # net accounts 결과에서 숫자 추출
    out = subprocess.run("net accounts", capture_output=True, text=True, shell=True, encoding='cp949').stdout
    
    duration = 0
    for line in out.splitlines():
        if "잠금 기간" in line or "Lockout duration" in line:
            duration = int(re.sub(r'[^0-9]', '', line))
            break
            
    if duration < 60:
        result["status"] = "취약"
        result["details"].append(f"계정 잠금 기간이 {duration}분입니다. (60분 이상 권고)")
    else:
        result["details"].append(f"계정 잠금 기간이 {duration}분으로 적절합니다.")
    return result

def check_w09():
    """W-09: 비밀번호 관리 정책 설정"""
    result = {"id": "W-09", "title": "비밀번호 관리 정책 설정", "status": "양호", "details": []}
    out = subprocess.run("net accounts", capture_output=True, text=True, shell=True, encoding='cp949').stdout
    
    # 최소 암호 길이 8자 기준
    match = re.search(r'(?:최소 암호 길이|Minimum password length).*: (\d+)', out)
    if match:
        length = int(match.group(1))
        if length < 8:
            result["status"] = "취약"
            result["details"].append(f"최소 암호 길이가 {length}자로 설정되어 보안에 취약합니다. (8자 이상 권장)")
    
    if not result["details"]:
        result["details"].append("기본적인 암호 정책 설정을 확인하였습니다.")
    return result

def check_w10():
    """W-10: 마지막 사용자 이름 표시 안 함"""
    result = {"id": "W-10", "title": "마지막 사용자 이름 표시 안 함", "status": "양호", "details": []}
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'dontdisplaylastusername'")
    
    val = data.get('dontdisplaylastusername') if isinstance(data, dict) else None
    if val == 1:
        result["details"].append("정책이 '사용(1)'으로 적절히 설정되어 있습니다.")
    else:
        result["status"] = "취약"
        result["details"].append("정책이 '사용 안 함(0)'으로 설정되어 마지막 로그인 계정이 노출됩니다.")
    return result

def check_w11():
    """W-11: 로컬 로그온 허용"""
    result = {"id": "W-11", "title": "로컬 로그온 허용", "status": "점검필요", "details": []}
    result["details"].append("로컬 로그온 권한은 정책 파일(secedit) 분석이 필요하므로 수동 점검을 권장합니다.")
    return result

def check_w12():
    """W-12: 익명 SID/이름 변환 허용 해제"""
    result = {"id": "W-12", "title": "익명 SID/이름 변환 허용 해제", "status": "양호", "details": []}
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LsaAnonymousNameLookup'")
    
    val = data.get('LsaAnonymousNameLookup') if isinstance(data, dict) else None
    if val == 1:
        result["status"] = "취약"
        result["details"].append("익명 SID 이름 변환이 허용(1)되어 있습니다.")
    else:
        result["details"].append("익명 SID 이름 변환이 차단(0)되어 있습니다.")
    return result

def check_w13():
    """W-13: 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"""
    result = {"id": "W-13", "title": "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한", "status": "양호", "details": []}
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'LimitBlankPasswordUse'")
    
    val = data.get('LimitBlankPasswordUse') if isinstance(data, dict) else None
    if val == 1:
        result["details"].append("빈 암호 사용 제한이 설정(1)되어 있습니다.")
    else:
        result["status"] = "취약"
        result["details"].append("빈 암호 사용 제한이 해제(0)되어 있습니다.")
    return result

def check_w14():
    """W-14: 원격터미널 접속 가능한 사용자 그룹 제한"""
    result = {"id": "W-14", "title": "원격터미널 접속 사용자 제한", "status": "양호", "details": []}
    data = run_ps("Get-LocalGroupMember -Group 'Remote Desktop Users' | Select-Object Name")
    
    if data:
        members = [m.get('Name') for m in data] if isinstance(data, list) else [data.get('Name')]
        result["details"].append(f"원격 접속 허용 리스트: {', '.join(members)}")
        result["status"] = "점검필요" # 관리자 외 계정 존재 시 확인 필요
    else:
        result["details"].append("Remote Desktop Users 그룹에 등록된 일반 사용자가 없습니다.")
    return result