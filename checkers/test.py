import subprocess
import json
import re
import csv
from datetime import datetime

def run_ps(cmd):
    """파워셀 명령 실행 후 JSON 반환"""
    full_cmd = f"powershell -Command \"{cmd} | ConvertTo-Json\""
    proc = subprocess.run(full_cmd, capture_output=True, text=True, shell=True)
    if proc.stdout.strip():
        try:
            return json.loads(proc.stdout)
        except:
            return proc.stdout.strip()
    return None
    
def check_w01():
    """W-01: Administrator 게정명 및 패스워드 정책 점검"""
    result = {"id": "W-01", "title": "Administrator 계정 이름 변경", "status": "양호", "details": []}
    data = run_ps("Get-LocalUser | Where-Object {$_.SID - like 'S-1 5-*-*-500} | Select-Object Name | ConvertTo-Json")

    if data:
        name = json.loads(data.stdout).get("Name", "")
        if name.lower() == "administrator":
            result["status"] = "취약" 
            result["details"].append(f"관리자 계정명('{name}')이 변경되지 않음")

    return result


def main():
    print(f"[{datetime.now()}] 주요정보통신기반시설 취약점 진단 **테스트 용** ")

    check_list = [check_w01]

    all_results = []
    for check_func in check_list:
        try:
            res = check_func()
            all_results.append(res)
            print(f"[*] {res['id']} {res['title']}: {res['status']}")
        except Exception as e:
            #실패 시 결과 구조를 유지 -> 통계 오류 방지
            error_res = {"id": "Error", "title": check_func.__name__, "status": "실패", "details": [str(e)]}
            all_results.append(error_res)
            print(f"[!] {check_func.__name__} 실행 실패: {e}")


if __name__ == "__main__":
    main()