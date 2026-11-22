"""Nhập danh sách chặn do BẠN tự chọn (định dạng hosts hoặc mỗi dòng một tên miền) vào bảng phân loại, nhóm 'inappropriate'.
Dùng: python tools/import_blocklist.py danhsach.txt  -> thêm vào common/ogk_common/data/classification.csv
Lưu ý quy định đồ án: KHÔNG dùng/đính kèm tên miền nội dung người lớn để thử nghiệm trong bộ test nộp bài."""
import csv, os, re, sys
path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "common", "ogk_common", "data", "classification.csv")
existing = {r["domain"] for r in csv.DictReader(open(path, encoding="utf-8"))}
new = []
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.split("#")[0].strip().split()
    d = (line[-1] if line else "").lower()
    if re.fullmatch(r"([a-z0-9-]{1,63}\.)+[a-z]{2,63}", d) and d not in existing: new.append(d); existing.add(d)
with open(path, "a", newline="", encoding="utf-8") as f:
    w = csv.writer(f); [w.writerow([d, "inappropriate", "nhập từ danh sách ngoài"]) for d in new]
print("Đã thêm", len(new), "tên miền")
