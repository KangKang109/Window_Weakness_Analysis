import csv
import json
from datetime import datetime
from checkers import account_mgmt, service_mgmt, patch_mgmt, log_mgmt, secure_mgmt

def main():
    print(f"[{datetime.now()}] 주요정보통신기반시설 취약점 진단 시작 (Windows 서버)")
    
    # 실행할 점검 함수 리스트 등록 (모든 항목 포함)
    check_list = [
        # 계정 관리 (W-01 ~ W-14)
        account_mgmt.check_w01, account_mgmt.check_w02, account_mgmt.check_w03,
        account_mgmt.check_w04, account_mgmt.check_w05, account_mgmt.check_w06,
        account_mgmt.check_w07, account_mgmt.check_w08, account_mgmt.check_w09,
        account_mgmt.check_w10, account_mgmt.check_w11, account_mgmt.check_w12,
        account_mgmt.check_w13, account_mgmt.check_w14,
        
        # 서비스 관리 (W-15 ~ W-37)
        service_mgmt.check_w15, service_mgmt.check_w16, service_mgmt.check_w17, 
        service_mgmt.check_w18, service_mgmt.check_w19, service_mgmt.check_w20,
        service_mgmt.check_w21, service_mgmt.check_w22, service_mgmt.check_w23, 
        service_mgmt.check_w24, service_mgmt.check_w25, service_mgmt.check_w26, 
        service_mgmt.check_w27, service_mgmt.check_w28, service_mgmt.check_w29, 
        service_mgmt.check_w30, service_mgmt.check_w31, service_mgmt.check_w32, 
        service_mgmt.check_w33, service_mgmt.check_w34, service_mgmt.check_w35, 
        service_mgmt.check_w36, service_mgmt.check_w37,
        
        # 패치 관리 (W-38 ~ W-39)
        patch_mgmt.check_w38, patch_mgmt.check_w39,
        
        # 로그 관리 (W-40 ~ W-43)
        log_mgmt.check_w40, log_mgmt.check_w41, 
        log_mgmt.check_w42, log_mgmt.check_w43,
        
        # 보안 관리 (W-44 ~ W-64)
        secure_mgmt.check_w44, secure_mgmt.check_w45, secure_mgmt.check_w46,
        secure_mgmt.check_w47, secure_mgmt.check_w48, secure_mgmt.check_w49,
        secure_mgmt.check_w50, secure_mgmt.check_w51, secure_mgmt.check_w52,
        secure_mgmt.check_w53, secure_mgmt.check_w54, secure_mgmt.check_w55,
        secure_mgmt.check_w56, secure_mgmt.check_w57, secure_mgmt.check_w58,
        secure_mgmt.check_w59, secure_mgmt.check_w60, secure_mgmt.check_w61,
        secure_mgmt.check_w62, secure_mgmt.check_w63, secure_mgmt.check_w64
    ]
    
    all_results = []
    
    for check_func in check_list:
        try:
            res = check_func()
            all_results.append(res)
            print(f"[*] {res['id']} {res['title']}: {res['status']}")
        except Exception as e:
            # 실패 시 결과 구조를 유지하여 통계 오류 방지
            error_res = {"id": "Error", "title": check_func.__name__, "status": "실패", "details": [str(e)]}
            all_results.append(error_res)
            print(f"[!] {check_func.__name__} 실행 실패: {e}")

    generate_reports(all_results)

def generate_reports(data):
    # 덮어쓰기를 위해 고정 파일명 사용
    json_file = "Audit_Report.json"
    csv_file = "Audit_Report.csv"

    # 1. 통계 산출
    total = len(data)
    pass_count = sum(1 for item in data if item['status'] == "양호")
    fail_count = sum(1 for item in data if item['status'] == "취약")
    manual_count = sum(1 for item in data if item['status'] == "점검필요")
    error_count = sum(1 for item in data if item['status'] == "실패")

    summary_str = f"전체: {total} | 양호: {pass_count} | 취약: {fail_count} | 점검필요: {manual_count} | 실패: {error_count}"

    # 2. JSON 저장
    report_data = {
        "summary": {
            "total": total,
            "pass": pass_count,
            "fail": fail_count,
            "manual": manual_count,
            "error": error_count,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        },
        "results": data
    }
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=4)

    # 3. CSV 저장 (엑셀용)
    with open(csv_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "점검항목", "결과", "상세내용"])
        for item in data:
            writer.writerow([item['id'], item['title'], item['status'], " | ".join(item['details'])])
        
        # CSV 최하단에 통계 추가
        writer.writerow([])
        writer.writerow(["[최종 요약]", summary_str])

    print("-" * 50)
    print(f"[진단 완료] {summary_str}")
    print(f"- {json_file}\n- {csv_file}")
    print("-" * 50)

if __name__ == "__main__":
    main()