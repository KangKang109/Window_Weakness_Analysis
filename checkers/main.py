import csv
import json
from datetime import datetime
import account_mgmt

def main():
    print(f"[{datetime.now()}] 주요정보통신기반시설 취약점 진단 시작 (Windows 서버)")
    
    # 실행할 점검 함수 리스트 등록
    check_list = [
        account_mgmt.check_w01, account_mgmt.check_w02, account_mgmt.check_w03,
        account_mgmt.check_w04, account_mgmt.check_w05, account_mgmt.check_w06,
        account_mgmt.check_w07, account_mgmt.check_w08, account_mgmt.check_w09,
        account_mgmt.check_w10, account_mgmt.check_w11, account_mgmt.check_w12,
        account_mgmt.check_w13, account_mgmt.check_w14
    ]
    
    all_results = []
    
    for check_func in check_list:
        try:
            res = check_func()
            all_results.append(res)
            print(f"[*] {res['id']} {res['title']}: {res['status']}")
        except Exception as e:
            print(f"[!] {check_func.__name__} 실행 실패: {e}")

    generate_reports(all_results)

def generate_reports(data):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"Audit_Report_{timestamp}.json"
    csv_file = f"Audit_Report_{timestamp}.csv"

    # JSON 저장
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

    # CSV 저장 (엑셀용)
    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "점검항목", "결과", "상세내용"])
        for item in data:
            writer.writerow([item['id'], item['title'], item['status'], " | ".join(item['details'])])

    print(f"\n[완료] 보고서가 생성되었습니다.\n- {json_file}\n- {csv_file}")

if __name__ == "__main__":
    main()