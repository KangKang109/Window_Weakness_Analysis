#secure_mgmt w-44 ~ w-64
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

def check_w44():
    """W-44: 원격 레지스트리 서비스 사용 여부"""
    result = {"id": "W-44", "title": "원격 레지스트리 서비스 사용 여부", "status": "양호", "details": []}
    svc = run_ps("Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue")
    
    if svc and svc.get('Status') == 4: # Running
        result["status"] = "취약"
        result["details"].append("Remote Registry 서비스가 실행 중입니다.")
    else:
        result["details"].append("Remote Registry 서비스가 중지되어 있거나 설치되지 않았습니다.")
    return result

def check_w45():
    """W-45: 백신 프로그램 설치 여부"""
    result = {"id": "W-45", "title": "백신 프로그램 설치", "status": "양호", "details": []}
    # 보안 센터를 통해 설치된 백신(Antivirus) 제품군 확인
    antivirus = run_ps("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct")
    
    if antivirus:
        names = [a.get('displayName') for a in antivirus] if isinstance(antivirus, list) else [antivirus.get('displayName')]
        result["details"].append(f"설치된 백신: {', '.join(names)}")
    else:
        result["status"] = "취약"
        result["details"].append("설치된 백신 프로그램이 탐지되지 않습니다.")
    return result

def check_w46():
    """W-46: SAM 파일 접근 통제 설정"""
    result = {"id": "W-46", "title": "SAM 파일 접근 통제 설정", "status": "양호", "details": []}
    sam_path = os.environ.get('SystemRoot') + "\\System32\\config\\SAM"
    acl = run_ps(f"Get-Acl '{sam_path}' | Select-Object -ExpandProperty Access")
    
    allowed_groups = ["Administrators", "SYSTEM"]
    if acl:
        if isinstance(acl, dict): acl = [acl]
        for entry in acl:
            identity = entry.get('IdentityReference', '')
            # 권장 그룹 외 다른 그룹/사용자가 포함되어 있는지 확인
            if not any(group in identity for group in allowed_groups):
                result["status"] = "취약"
                result["details"].append(f"SAM 파일에 권장되지 않는 권한이 포함되어 있습니다: {identity}")
                break
    
    if result["status"] == "양호":
        result["details"].append("SAM 파일 권한이 Administrators 및 SYSTEM으로 제한되어 있습니다.")
    return result

def check_w47():
    """W-47: 화면 보호기 설정"""
    result = {"id": "W-47", "title": "화면 보호기 설정", "status": "양호", "details": []}
    # 현재 로그인한 사용자의 화면 보호기 설정 확인
    reg_path = "HKCU:\\Control Panel\\Desktop"
    active = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'ScreenSaveActive' -ErrorAction SilentlyContinue")
    timeout = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'ScreenSaveTimeOut' -ErrorAction SilentlyContinue")
    secure = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue")
    
    is_active = active.get('ScreenSaveActive') == "1" if isinstance(active, dict) else False
    tout_val = int(timeout.get('ScreenSaveTimeOut', 9999)) if isinstance(timeout, dict) else 9999
    is_secure = secure.get('ScreenSaverIsSecure') == "1" if isinstance(secure, dict) else False
    
    if not is_active or tout_val > 600 or not is_secure:
        result["status"] = "취약"
        result["details"].append(f"화면보호기 미설정 또는 기준 미달(대기시간: {tout_val}초, 암호사용: {is_secure})")
    else:
        result["details"].append(f"화면보호기가 적절히 설정되었습니다 (대기시간: {tout_val}초).")
    return result

def check_w48():
    """W-48: 로그온하지 않고 시스템 종료 허용 안 함"""
    result = {"id": "W-48", "title": "로그온하지 않고 시스템 종료 허용 안 함", "status": "양호", "details": []}
    reg_path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'shutdownwithoutlogon' -ErrorAction SilentlyContinue")
    
    val = data.get('shutdownwithoutlogon') if isinstance(data, dict) else 1
    if val == 1: # 1: 허용(취약)
        result["status"] = "취약"
        result["details"].append("로그온 화면에서 시스템 종료 버튼이 활성화(1)되어 있습니다.")
    else:
        result["details"].append("로그온 화면에서 시스템 종료 버튼이 비활성화(0)되어 있습니다.")
    return result

def check_w49():
    """W-49: 원격 시스템에서 강제로 시스템 종료 (권한 확인)"""
    result = {"id": "W-49", "title": "원격 시스템에서 강제로 시스템 종료", "status": "점검필요", "details": []}
    result["details"].append("사용자 권한 할당(SeRemoteShutdownPrivilege) 정책은 secedit 분석이 필요하므로 수동 점검을 권장합니다.")
    return result

def check_w50():
    """W-50: 보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료 (사용 안 함 권고)"""
    result = {"id": "W-50", "title": "보안 감사를 로그 할 수 없는 경우 즉시 시스템 종료", "status": "양호", "details": []}
    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'CrashOnAuditFail' -ErrorAction SilentlyContinue")
    
    val = data.get('CrashOnAuditFail') if isinstance(data, dict) else 0
    if val != 0: # 0이 아니면 활성(취약)
        result["status"] = "취약"
        result["details"].append("감사 로그 실패 시 시스템 종료 정책이 활성화되어 있습니다.")
    else:
        result["details"].append("해당 정책이 '사용 안 함(0)'으로 설정되어 있습니다.")
    return result

def check_w51():
    """W-51: SAM 계정과 공유의 익명 열거 허용 안 함"""
    result = {"id": "W-51", "title": "SAM 계정과 공유의 익명 열거 허용 안 함", "status": "양호", "details": []}
    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'RestrictAnonymousSAM' -ErrorAction SilentlyContinue")
    
    val = data.get('RestrictAnonymousSAM') if isinstance(data, dict) else 0
    if val == 0: # 0: 허용(취약)
        result["status"] = "취약"
        result["details"].append("SAM 계정 및 공유의 익명 열거가 허용(0)되어 있습니다.")
    else:
        result["details"].append("익명 열거가 차단(1)되어 있습니다.")
    return result

def check_w52():
    """W-52: Autologon 기능 제어"""
    result = {"id": "W-52", "title": "Autologon 기능 제어", "status": "양호", "details": []}
    reg_path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'AutoAdminLogon' -ErrorAction SilentlyContinue")
    
    val = str(data.get('AutoAdminLogon')) if isinstance(data, dict) else "0"
    if val == "1":
        result["status"] = "취약"
        result["details"].append("자동 로그온(AutoAdminLogon) 기능이 활성화(1)되어 있습니다.")
    else:
        result["details"].append("자동 로그온 기능이 비활성화(0)되어 있거나 설정이 존재하지 않습니다.")
    return result

def check_w53():
    """W-53: 이동식 미디어 포맷 및 꺼내기 허용"""
    result = {"id": "W-53", "title": "이동식 미디어 포맷 및 꺼내기 허용", "status": "양호", "details": []}
    # 0: Administrators, 1: Administrators and Power Users, 2: Administrators and Interactive Users
    reg_path = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'AllocateDASD' -ErrorAction SilentlyContinue")
    
    val = data.get('AllocateDASD') if isinstance(data, dict) else "0"
    if str(val) != "0":
        result["status"] = "취약"
        result["details"].append(f"이동식 미디어 포맷 권한이 Administrators 외에 부여되어 있습니다(값: {val}).")
    else:
        result["details"].append("이동식 미디어 포맷 권한이 Administrators로 제한되어 있습니다.")
    return result

def check_w54():
    """W-54: Dos 공격 방어 레지스트리 설정"""
    result = {"id": "W-54", "title": "DoS 공격 방어 레지스트리 설정", "status": "양호", "details": []}
    tcp_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
    
    # 4가지 필수 레지스트리 체크
    checks = {
        "SynAttackProtect": 1,
        "EnableDeadGWDetect": 0,
        "KeepAliveTime": 300000,
        "NoNameReleaseOnDemand": 1
    }
    
    for key, expected in checks.items():
        data = run_ps(f"Get-ItemProperty -Path '{tcp_path}' -Name '{key}' -ErrorAction SilentlyContinue")
        val = data.get(key) if isinstance(data, dict) else None
        
        if val is None or (key == "SynAttackProtect" and int(val) < expected) or (key != "SynAttackProtect" and int(val) != expected):
            result["status"] = "취약"
            result["details"].append(f"{key} 설정이 부적절합니다 (현재값: {val}, 권장값: {expected})")
            
    if result["status"] == "양호":
        result["details"].append("모든 DoS 방어 레지스트리 설정이 권고치에 부합합니다.")
    return result

def check_w55():
    """W-55: 사용자가 프린터 드라이버를 설치할 수 없게 함"""
    result = {"id": "W-55", "title": "사용자의 프린터 드라이버 설치 차단", "status": "양호", "details": []}
    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'AddPrinterDrivers' -ErrorAction SilentlyContinue")
    
    # 1: 사용(취약), 0: 사용안함(양호) - 정책명이 '설치할 수 없게 함'이므로 논리 주의
    val = data.get('AddPrinterDrivers') if isinstance(data, dict) else 0
    if val == 1:
        result["status"] = "취약"
        result["details"].append("일반 사용자가 프린터 드라이버를 설치할 수 있도록 설정되어 있습니다.")
    else:
        result["details"].append("프린터 드라이버 설치 권한이 제한되어 있습니다.")
    return result

def check_w56():
    """W-56: SMB 세션 중단 관리 설정"""
    result = {"id": "W-56", "title": "SMB 세션 중단 관리 설정", "status": "양호", "details": []}
    # 유휴 시간 설정 (AutoDisconnect)
    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'autodisconnect' -ErrorAction SilentlyContinue")
    
    val = data.get('autodisconnect') if isinstance(data, dict) else 15
    if int(val) > 15:
        result["status"] = "취약"
        result["details"].append(f"SMB 유휴 세션 끊기 시간이 15분을 초과합니다({val}분).")
    else:
        result["details"].append(f"SMB 유휴 세션 설정이 적절합니다({val}분).")
    return result

def check_w57():
    """W-57: 로그온 시 경고 메시지 설정"""
    result = {"id": "W-57", "title": "로그온 시 경고 메시지 설정", "status": "양호", "details": []}
    reg_path = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    title = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'legalnoticecaption' -ErrorAction SilentlyContinue")
    text = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'legalnoticetext' -ErrorAction SilentlyContinue")
    
    t_val = title.get('legalnoticecaption') if isinstance(title, dict) else ""
    x_val = text.get('legalnoticetext') if isinstance(text, dict) else ""
    
    if not t_val or not x_val:
        result["status"] = "취약"
        result["details"].append("로그온 경고 메시지 제목 또는 내용이 설정되어 있지 않습니다.")
    else:
        result["details"].append(f"설정된 제목: {t_val}")
    return result

def check_w58():
    """W-58: 사용자별 홈 디렉터리 권한 설정"""
    result = {"id": "W-58", "title": "사용자별 홈 디렉터리 권한 설정", "status": "양호", "details": []}
    # C:\Users 폴더 내 개별 사용자 폴더의 Everyone 권한 체크
    users_path = "C:\\Users"
    sub_dirs = run_ps(f"Get-ChildItem -Path '{users_path}' -Directory")
    
    if sub_dirs:
        if isinstance(sub_dirs, dict): sub_dirs = [sub_dirs]
        for dir_info in sub_dirs:
            name = dir_info.get('Name')
            if name in ['Public', 'All Users', 'Default', 'Default User']: continue
            
            path = os.path.join(users_path, name)
            acl = run_ps(f"Get-Acl '{path}' | Select-Object -ExpandProperty Access")
            if acl:
                if isinstance(acl, dict): acl = [acl]
                if any(a.get('IdentityReference') == 'Everyone' for a in acl):
                    result["status"] = "취약"
                    result["details"].append(f"홈 디렉터리 [{name}]에 Everyone 권한이 있습니다.")
    
    if not result["details"]:
        result["details"].append("모든 홈 디렉터리에 Everyone 권한이 제한되어 있습니다.")
    return result

def check_w59():
    """W-59: LAN Manager 인증 수준"""
    result = {"id": "W-59", "title": "LAN Manager 인증 수준", "status": "양호", "details": []}
    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'LmCompatibilityLevel' -ErrorAction SilentlyContinue")
    
    # 3 이상: NTLMv2 응답만 보냄
    val = data.get('LmCompatibilityLevel') if isinstance(data, dict) else 0
    if int(val) < 3:
        result["status"] = "취약"
        result["details"].append(f"LAN Manager 인증 수준이 낮게 설정되어 있습니다(값: {val}). NTLMv2 이상 권고.")
    else:
        result["details"].append(f"LAN Manager 인증 수준이 적절합니다(값: {val}).")
    return result

def check_w60():
    """W-60: 보안 채널 데이터 디지털 암호화 또는 서명"""
    result = {"id": "W-60", "title": "보안 채널 데이터 디지털 암호화 또는 서명", "status": "양호", "details": []}
    reg_path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"
    
    policies = {
        "RequireSignOrSeal": 1,
        "RequireStrongKey": 1,
        "SealSecureChannel": 1
    }
    
    for p, expected in policies.items():
        data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name '{p}' -ErrorAction SilentlyContinue")
        val = data.get(p) if isinstance(data, dict) else 0
        if int(val) != expected:
            result["status"] = "취약"
            result["details"].append(f"{p} 정책이 비활성화(0)되어 있습니다.")
            
    if result["status"] == "양호":
        result["details"].append("모든 보안 채널 암호화/서명 정책이 활성화되어 있습니다.")
    return result

def check_w61():
    """W-61: 파일 및 디렉토리 보호 (NTFS 사용 여부)"""
    result = {"id": "W-61", "title": "NTFS 파일 시스템 사용 여부", "status": "양호", "details": []}
    volumes = run_ps("Get-Volume | Where-Object { $_.DriveLetter -ne $null }")
    
    if volumes:
        if isinstance(volumes, dict): volumes = [volumes]
        for vol in volumes:
            if vol.get('FileSystemType') != 'NTFS':
                result["status"] = "취약"
                result["details"].append(f"드라이브 {vol.get('DriveLetter')}:가 NTFS가 아닙니다({vol.get('FileSystemType')}).")
                
    if not result["details"]:
        result["details"].append("모든 로컬 드라이브가 NTFS 파일 시스템을 사용 중입니다.")
    return result

def check_w62():
    """W-62: 시작 프로그램 목록 분석"""
    result = {"id": "W-62", "title": "시작 프로그램 목록 분석", "status": "점검필요", "details": []}
    # 레지스트리 Run 키 목록 추출
    run_list = run_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'")
    if run_list:
        items = [k for k in run_list.keys() if k not in ['PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider']]
        result["details"].append(f"등록된 시작 프로그램: {', '.join(items)}")
    result["details"].append("시작 프로그램 중 출처가 불분명한 항목이 있는지 수동 검토하십시오.")
    return result

def check_w63():
    """W-63: 도메인 컨트롤러-사용자의 시간 동기화"""
    result = {"id": "W-63", "title": "도메인 컨트롤러 시간 동기화 오차", "status": "양호", "details": []}
    # Kerberos 정책 (MaxTolerance: 분 단위) - 로컬 정책 추출 필요
    result["details"].append("Kerberos 시계 동기화 최대 허용 오차는 기본 5분입니다. GPO에서 확인하십시오.")
    return result

def check_w64():
    """W-64: 윈도우 방화벽 설정"""
    result = {"id": "W-64", "title": "윈도우 방화벽 설정", "status": "양호", "details": []}
    fw_state = run_ps("Get-NetFirewallProfile | Select-Object Name, Enabled")
    
    if fw_state:
        if isinstance(fw_state, dict): fw_state = [fw_state]
        for profile in fw_state:
            if profile.get('Enabled') is False:
                result["status"] = "취약"
                result["details"].append(f"방화벽 프로필 [{profile.get('Name')}]이 비활성화되어 있습니다.")
                
    if result["status"] == "양호":
        result["details"].append("모든 방화벽 프로필(Domain, Private, Public)이 활성화되어 있습니다.")
    return result