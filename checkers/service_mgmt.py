
import subprocess
import json
import platform

def run_ps(cmd):
    """파워셸 명령 실행 후 JSON 또는 문자열 반환"""
    full_cmd = f"powershell -Command \"{cmd} | ConvertTo-Json\""
    proc = subprocess.run(full_cmd, capture_output=True, text=True, shell=True)
    if proc.stdout.strip():
        try:
            return json.loads(proc.stdout)
        except:
            return proc.stdout.strip()
    return None


#서비스 관리(W-15~W-37)
def check_w15():
    """W-15: 사용자 개인키 사용 시 암호 입력"""
    result = {"id": "W-15", "title": "사용자 개인키 사용 시 암호 입력", "status": "양호", "details": []}
    # 레지스트리 값 확인 (2: 매번 암호 입력 필요)
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Cryptography' -Name 'ForceKeyProtection' -ErrorAction SilentlyContinue")
    
    val = data.get('ForceKeyProtection') if isinstance(data, dict) else None
    if val == 2:
        result["details"].append("강력한 키 보호 정책이 설정되어 있습니다. (값: 2)")
    else:
        result["status"] = "취약"
        result["details"].append("사용자 키에 대해 강력한 키 보호가 설정되어 있지 않습니다.")
    return result

def check_w16():
    """W-16: 공유 권한 및 사용자 그룹 설정"""
    result = {"id": "W-16", "title": "공유 권한 및 사용자 그룹 설정", "status": "양호", "details": []}
    # 일반 공유 디렉터리 중 Everyone 권한 확인
    shares = run_ps("Get-SmbShare | Where-Object { $_.Name -notlike '*$' }")
    
    if shares:
        if isinstance(shares, dict): shares = [shares]
        for share in shares:
            name = share.get('Name')
            access = run_ps(f"Get-SmbShareAccess -Name '{name}'")
            if isinstance(access, dict): access = [access]
            for acc in access:
                if acc.get('AccountName') == 'Everyone':
                    result["status"] = "취약"
                    result["details"].append(f"공유 폴더 [{name}]에 Everyone 권한이 존재합니다.")
    
    if not result["details"]:
        result["details"].append("Everyone 권한이 설정된 일반 공유 폴더가 없습니다.")
    return result

def check_w17():
    """W-17: 하드디스크 기본 공유 제거"""
    result = {"id": "W-17", "title": "하드디스크 기본 공유 제거", "status": "양호", "details": []}
    # AutoShareServer 레지스트리 확인 (0이어야 양호)
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'AutoShareServer' -ErrorAction SilentlyContinue")
    
    val = data.get('AutoShareServer') if isinstance(data, dict) else None
    if val != 0:
        result["status"] = "취약"
        result["details"].append("AutoShareServer 정책이 설정되지 않았거나 활성화(1)되어 있습니다.")
    else:
        result["details"].append("기본 공유 자동 생성 정책이 비활성화(0)되어 있습니다.")
    return result

def check_w18():
    """W-18: 불필요한 서비스 제거"""
    result = {"id": "W-18", "title": "불필요한 서비스 제거", "status": "양호", "details": []}
    # 가이드상 불필요한 서비스 예시 목록 (Alerter, Messenger, TlntSvr 등)
    unnecessary_services = ['Alerter', 'Messenger', 'Simple TCP/IP Services', 'Telnet']
    
    found_services = []
    for svc_name in unnecessary_services:
        svc = run_ps(f"Get-Service -Name '{svc_name}' -ErrorAction SilentlyContinue")
        if svc and svc.get('Status') == 4: # 4: Running
            found_services.append(svc_name)
    
    if found_services:
        result["status"] = "취약"
        result["details"].append(f"불필요한 서비스가 구동 중입니다: {', '.join(found_services)}")
    else:
        result["details"].append("주요 불필요 서비스가 모두 중지되어 있습니다.")
    return result

def check_w19():
    """W-19: 불필요한 IIS 서비스 구동 점검"""
    result = {"id": "W-19", "title": "불필요한 IIS 서비스 구동 점검", "status": "양호", "details": []}
    iis_svc = run_ps("Get-Service -Name 'W3SVC' -ErrorAction SilentlyContinue")
    
    if iis_svc and iis_svc.get('Status') == 4:
        result["status"] = "점검필요"
        result["details"].append("IIS 서비스(W3SVC)가 실행 중입니다. 실제 사용 여부 확인이 필요합니다.")
    else:
        result["details"].append("IIS 서비스가 설치되어 있지 않거나 중지 상태입니다.")
    return result

def check_w20():
    """W-20: NetBIOS 바인딩 서비스 구동 점검"""
    result = {"id": "W-20", "title": "NetBIOS 바인딩 서비스 구동 점검", "status": "양호", "details": []}
    # NetBIOS over TCP/IP 설정 확인 (2: Disabled)
    netbios_info = run_ps("Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object TcpipNetbiosOptions")
    
    if netbios_info:
        if isinstance(netbios_info, dict): netbios_info = [netbios_info]
        for adapter in netbios_info:
            if adapter.get('TcpipNetbiosOptions') != 2:
                result["status"] = "취약"
                result["details"].append("일부 어댑터에 NetBIOS 바인딩이 활성화되어 있습니다.")
                break
    
    if result["status"] == "양호":
        result["details"].append("모든 활성 어댑터에서 NetBIOS 바인딩이 해제되어 있습니다.")
    return result

def check_w21():
    """W-21: 암호화되지 않는 FTP 서비스 비활성화"""
    result = {"id": "W-21", "title": "암호화되지 않는 FTP 서비스 비활성화", "status": "양호", "details": []}
    ftp_svc = run_ps("Get-Service -Name 'ftpsvc' -ErrorAction SilentlyContinue")
    
    if ftp_svc and ftp_svc.get('Status') == 4:
        result["status"] = "취약"
        result["details"].append("기본 FTP 서비스(ftpsvc)가 실행 중입니다. SFTP 사용을 권고합니다.")
    else:
        result["details"].append("암호화되지 않은 기본 FTP 서비스가 중지되어 있습니다.")
    return result

def check_w22():
    """W-22: FTP 디렉토리 접근권한 설정"""
    result = {"id": "W-22", "title": "FTP 디렉토리 접근권한 설정", "status": "양호", "details": []}
    # FTP 서비스가 구동 중일 때만 점검
    ftp_svc = run_ps("Get-Service -Name 'ftpsvc' -ErrorAction SilentlyContinue")
    if ftp_svc and ftp_svc.get('Status') == 4:
        # FTP 홈 디렉토리(기본값 C:\inetpub\ftproot) 권한 확인
        acl = run_ps("Get-Acl 'C:\\inetpub\\ftproot' | Select-Object -ExpandProperty Access")
        if acl:
            if isinstance(acl, dict): acl = [acl]
            for entry in acl:
                if entry.get('IdentityReference') == 'Everyone':
                    result["status"] = "취약"
                    result["details"].append("FTP 홈 디렉토리에 Everyone 권한이 설정되어 있습니다.")
                    break
    else:
        result["details"].append("FTP 서비스가 비활성화되어 있어 점검 대상이 아닙니다.")
    return result

def check_w23():
    """W-23: 공유 서비스에 대한 익명 접근 제한 설정"""
    result = {"id": "W-23", "title": "공유 서비스에 대한 익명 접근 제한 설정", "status": "양호", "details": []}
    # RestrictAnonymous 값이 1 또는 2여야 양호 (0이면 취약)
    data = run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RestrictAnonymous' -ErrorAction SilentlyContinue")
    
    val = data.get('RestrictAnonymous') if isinstance(data, dict) else 0
    if val == 0:
        result["status"] = "취약"
        result["details"].append("익명 연결에 대한 제한(RestrictAnonymous)이 설정되어 있지 않습니다(0).")
    else:
        result["details"].append(f"익명 연결 제한이 설정되어 있습니다(값: {val}).")
    return result

def check_w24():
    """W-24: FTP 접근 제어 설정 (IP 제한 여부)"""
    result = {"id": "W-24", "title": "FTP 접근 제어 설정", "status": "양호", "details": []}
    # IIS FTP 서비스가 설치되어 있는지 확인
    ftp_check = run_ps("Get-Service -Name 'ftpsvc' -ErrorAction SilentlyContinue")
    if ftp_check and ftp_check.get('Status') == 4:
        # WebAdministration 모듈을 사용하여 IP 제한 설정 확인
        cmd = "Import-Module WebAdministration; Get-WebConfigurationProperty -Filter /system.ftpServer/security/ipSecurity -Name allowUnlisted -PSPath 'IIS:\\' "
        ip_sec = run_ps(cmd)
        
        # allowUnlisted가 False여야 화이트리스트 방식(양호)
        if ip_sec is True or ip_sec == "True":
            result["status"] = "취약"
            result["details"].append("FTP 서비스가 모든 IP의 접속을 허용하고 있습니다(IP 제한 미설정).")
        else:
            result["details"].append("FTP 서비스에 IP 주소 제한 설정이 적용되어 있습니다.")
    else:
        result["details"].append("FTP 서비스가 비활성화되어 있습니다.")
    return result

def check_w25():
    """W-25: DNS Zone Transfer 설정"""
    result = {"id": "W-25", "title": "DNS Zone Transfer 설정", "status": "양호", "details": []}
    dns_svc = run_ps("Get-Service -Name 'DNS' -ErrorAction SilentlyContinue")
    
    if dns_svc and dns_svc.get('Status') == 4:
        # 영역 전송 설정(SecureResponses) 확인
        zones = run_ps("Get-DnsServerZone")
        if zones:
            if isinstance(zones, dict): zones = [zones]
            for zone in zones:
                if zone.get('SecureSecondaries') == 'TransferAnyServer':
                    result["status"] = "취약"
                    result["details"].append(f"DNS 영역 [{zone.get('ZoneName')}]이 모든 서버로의 영역 전송을 허용하고 있습니다.")
    else:
        result["details"].append("DNS 서비스가 설치되어 있지 않거나 중지 상태입니다.")
    return result

def check_w26():
    """W-26: RDS(Remote Data Services) 제거"""
    result = {"id": "W-26", "title": "RDS(Remote Data Services) 제거", "status": "양호", "details": []}
    # Windows 2008 이상은 기본적으로 양호로 간주되나, 가상 디렉토리 존재 여부 체크
    if int(platform.release().split('.')[0]) < 6: # 구형 OS 체크
        msadc_path = "C:\\Program Files\\Common Files\\System\\msadc"
        check_dir = run_ps(f"Test-Path '{msadc_path}'")
        if check_dir is True:
            result["status"] = "취약"
            result["details"].append("구형 OS에서 RDS 관련 MSADC 디렉토리가 존재합니다.")
    else:
        result["details"].append("최신 OS 버전이며 RDS 취약점 대상이 아닙니다.")
    return result

def check_w27():
    """W-27: 최신 Windows OS Build 버전 적용"""
    result = {"id": "W-27", "title": "최신 Windows OS Build 버전 적용", "status": "점검필요", "details": []}
    os_info = run_ps("Get-ComputerInfo | Select-Object WindowsVersion, WindowsBuildLabEx, CsCaption")
    result["details"].append(f"현재 버전: {os_info.get('CsCaption')}, 빌드: {os_info.get('WindowsBuildLabEx')}")
    result["details"].append("최신 보안 패치 적용 여부를 업데이트 관리 대장과 대조하십시오.")
    return result

def check_w28():
    """W-28: 터미널 서비스 암호화 수준 설정"""
    result = {"id": "W-28", "title": "터미널 서비스 암호화 수준 설정", "status": "양호", "details": []}
    # 암호화 수준 레지스트리 확인 (MinEncryptionLevel: 3이 고수준)
    reg_path = 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'MinEncryptionLevel' -ErrorAction SilentlyContinue")
    
    level = data.get('MinEncryptionLevel') if isinstance(data, dict) else 0
    if level < 2: # 2: Client Compatible, 3: High, 4: FIPS Compliant
        result["status"] = "취약"
        result["details"].append(f"RDP 암호화 수준이 낮게 설정되어 있습니다(값: {level}).")
    else:
        result["details"].append(f"RDP 암호화 수준이 적절합니다(값: {level}).")
    return result

def check_w29():
    """W-29: 불필요한 SNMP 서비스 구동 점검"""
    result = {"id": "W-29", "title": "불필요한 SNMP 서비스 구동 점검", "status": "양호", "details": []}
    snmp_svc = run_ps("Get-Service -Name 'SNMP' -ErrorAction SilentlyContinue")
    
    if snmp_svc and snmp_svc.get('Status') == 4:
        result["status"] = "점검필요"
        result["details"].append("SNMP 서비스가 실행 중입니다. NMS 모니터링 등 용도가 명확한지 확인하십시오.")
    else:
        result["details"].append("SNMP 서비스가 중지되어 있거나 설치되지 않았습니다.")
    return result

def check_w30():
    """W-30: SNMP Community String 복잡성 설정"""
    result = {"id": "W-30", "title": "SNMP Community String 복잡성 설정", "status": "양호", "details": []}
    # SNMP Community 정보는 레지스트리에 저장됨
    reg_path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\ValidCommunities'
    communities = run_ps(f"Get-ItemProperty -Path '{reg_path}' -ErrorAction SilentlyContinue")
    
    if communities:
        # 가이드상 금지 단어
        forbidden = ['public', 'private']
        found_bad = [c for c in communities.keys() if c.lower() in forbidden]
        
        if found_bad:
            result["status"] = "취약"
            result["details"].append(f"기본 Community String({', '.join(found_bad)})이 사용되고 있습니다.")
        else:
            result["details"].append("기본 Community String이 변경되어 있습니다.")
    return result

def check_w31():
    """W-31: SNMP Access Control 설정"""
    result = {"id": "W-31", "title": "SNMP Access Control 설정", "status": "양호", "details": []}
    # SNMP 허용 호스트 레지스트리 확인
    reg_path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\SNMP\\Parameters\\PermittedManagers'
    managers = run_ps(f"Get-ItemProperty -Path '{reg_path}' -ErrorAction SilentlyContinue")
    
    # 0이 아닌 호스트 리스트가 등록되어 있는지 확인
    if managers:
        hosts = [str(v) for k, v in managers.items() if k not in ['PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider']]
        if not hosts:
            result["status"] = "취약"
            result["details"].append("모든 호스트로부터 SNMP 패킷을 수용하도록 설정되어 있습니다.")
        else:
            result["details"].append(f"허용된 SNMP 호스트: {', '.join(hosts)}")
    else:
        # 서비스 미구동 시 양호 처리 (W-29 연동)
        result["details"].append("SNMP 서비스가 미구동 중이거나 접근 제어 설정이 비어있습니다.")
    return result

def check_w32():
    """W-32: DNS 서비스 구동 점검 (동적 업데이트)"""
    result = {"id": "W-32", "title": "DNS 서비스 동적 업데이트 설정", "status": "양호", "details": []}
    dns_check = run_ps("Get-DnsServerZone -ErrorAction SilentlyContinue")
    
    if dns_check:
        if isinstance(dns_check, dict): dns_check = [dns_check]
        for zone in dns_check:
            # DynamicUpdate 설정이 None(0)이 아니면 취약
            if zone.get('DynamicUpdate') != 'None':
                result["status"] = "취약"
                result["details"].append(f"DNS 영역 [{zone.get('ZoneName')}]에 동적 업데이트가 활성화되어 있습니다.")
    else:
        result["details"].append("DNS 서비스가 비활성화되어 있습니다.")
    return result

def check_w33():
    """W-33: HTTP/FTP/SMTP 배너 차단"""
    result = {"id": "W-33", "title": "HTTP/FTP/SMTP 배너 차단", "status": "점검필요", "details": []}
    # IIS 배너 차단 여부 (X-Powered-By 등 헤더 삭제 확인)
    iis_check = run_ps("Get-WebConfigurationProperty -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -PSPath 'IIS:\\'")
    result["details"].append("HTTP 헤더 및 FTP 응답 메시지에서 버전 정보 노출 여부를 수동으로 확인하십시오.")
    return result

def check_w34():
    """W-34: Telnet 서비스 비활성화"""
    result = {"id": "W-34", "title": "Telnet 서비스 비활성화 및 인증 설정", "status": "양호", "details": []}
    telnet_svc = run_ps("Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue")
    
    if telnet_svc and telnet_svc.get('Status') == 4:
        # 인증 방법 확인 (NTLM 전용 여부 - 레지스트리 NTLM 값 확인)
        reg_path = 'HKLM:\\SOFTWARE\\Microsoft\\TelnetServer\\1.0'
        auth_data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'NTLM' -ErrorAction SilentlyContinue")
        if auth_data and auth_data.get('NTLM') != 2: # 2: NTLM Only
            result["status"] = "취약"
            result["details"].append("Telnet 서비스가 가동 중이며 NTLM 전용 인증이 설정되지 않았습니다.")
    else:
        result["details"].append("Telnet 서비스가 설치되어 있지 않거나 중지 상태입니다.")
    return result

def check_w35():
    """W-35: 불필요한 ODBC/OLE-DB 데이터 소스 제거"""
    result = {"id": "W-35", "title": "불필요한 ODBC 데이터 소스 점검", "status": "점검필요", "details": []}
    # 시스템 DSN 목록 추출
    dsn_list = run_ps("Get-OdbcDsn -DsnType 'System' -ErrorAction SilentlyContinue")
    if dsn_list:
        names = [d.get('Name') for d in dsn_list] if isinstance(dsn_list, list) else [dsn_list.get('Name')]
        result["details"].append(f"등록된 시스템 DSN: {', '.join(names)}")
        result["details"].append("사용하지 않는 불필요한 데이터 소스가 있는지 확인하십시오.")
    else:
        result["status"] = "양호"
        result["details"].append("등록된 시스템 DSN이 없습니다.")
    return result

def check_w36():
    """W-36: 원격터미널 접속 타임아웃 설정 (30분 이하)"""
    result = {"id": "W-36", "title": "원격터미널 접속 타임아웃 설정", "status": "양호", "details": []}
    # RDP-Tcp 세션 타임아웃 레지스트리 (MaxIdleTime: 밀리초 단위)
    reg_path = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp'
    data = run_ps(f"Get-ItemProperty -Path '{reg_path}' -Name 'MaxIdleTime' -ErrorAction SilentlyContinue")
    
    # 30분 = 1,800,000 ms
    idle_time = data.get('MaxIdleTime') if isinstance(data, dict) else 0
    if idle_time == 0 or idle_time > 1800000:
        result["status"] = "취약"
        result["details"].append(f"원격 터미널 유휴 시간 제한이 설정되지 않았거나 30분을 초과합니다({idle_time}ms).")
    else:
        result["details"].append(f"유휴 시간 제한이 {idle_time // 60000}분으로 적절합니다.")
    return result

def check_w37():
    """W-37: 예약된 작업에 의심스러운 명령 등록 점검"""
    result = {"id": "W-37", "title": "의심스러운 예약 작업 점검", "status": "점검필요", "details": []}
    # 실행 중인 예약 작업 리스트 추출
    tasks = run_ps("Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | Select-Object TaskName, TaskPath")
    
    if tasks:
        # 모든 작업을 나열하기엔 너무 많으므로 요약 정보만 제공
        total_tasks = len(tasks) if isinstance(tasks, list) else 1
        result["details"].append(f"현재 {total_tasks}개의 활성화된 예약 작업이 존재합니다.")
        result["details"].append("정기적으로 의심스러운 스크립트(.bat, .ps1, .vbs)가 등록되어 있는지 검토하십시오.")
    return result