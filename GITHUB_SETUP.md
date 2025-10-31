# Hướng dẫn đẩy dự án lên GitHub

## Cách 1: Sử dụng script tự động (Khuyến nghị)

### Bước 1: Tạo GitHub Personal Access Token
1. Truy cập: https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Đặt tên: `Create Repo Token`
4. Chọn scope: **repo** (đầy đủ quyền)
5. Click "Generate token"
6. **Copy token ngay** (chỉ hiển thị 1 lần)

### Bước 2: Chạy script tạo repository
```powershell
.\create_github_repo.ps1 -Token YOUR_TOKEN_HERE
```

Script sẽ tự động:
- Tạo repository private với tên: `AI-Powered-Alert-Prioritization-for-Wazuh`
- Thêm remote origin
- Hiển thị lệnh để push code

### Bước 3: Push code lên GitHub
Sau khi script chạy xong, thực hiện:
```powershell
git branch -M main
git push -u origin main
```

---

## Cách 2: Tạo repository thủ công

### Bước 1: Tạo repository trên GitHub
1. Truy cập: https://github.com/new
2. Repository name: `AI-Powered-Alert-Prioritization-for-Wazuh`
3. Description: `AI-powered security alert prioritization pipeline for Wazuh with LLM analysis and TheHive integration`
4. Chọn **Private**
5. **KHÔNG** check "Add a README file" (vì đã có sẵn)
6. Click "Create repository"

### Bước 2: Kết nối và push code
Sau khi tạo repo, chạy các lệnh sau:

```powershell
# Thêm remote
git remote add origin https://github.com/lethanhsang188/AI-Powered-Alert-Prioritization-for-Wazuh.git

# Đổi tên branch thành main
git branch -M main

# Push code lên GitHub
git push -u origin main
```

Nếu GitHub yêu cầu authentication, bạn có thể:
- Sử dụng GitHub Personal Access Token làm password
- Hoặc cài đặt GitHub Desktop
- Hoặc cấu hình SSH key

---

## Sau khi push thành công

Repository của bạn sẽ có:
- ✅ Toàn bộ source code
- ✅ Docker configuration
- ✅ Documentation (README, GAPS_ANALYSIS)
- ✅ Tests
- ✅ .gitignore (đã exclude .env, logs, state files)

**Lưu ý**: File `.env` sẽ **KHÔNG** được push lên GitHub (đã có trong .gitignore) để bảo mật.

