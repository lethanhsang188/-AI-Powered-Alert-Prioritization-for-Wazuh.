# ⚠️ GitHub Push Security Notice

## ✅ Đã Push Thành Công

Code đã được push lên: https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh.

**Commit:** `20bb4e4` - feat: Add supply chain attack detection, CSRF detection, attack type normalization, and Tier 3 attack detection

---

## 🔒 Bảo Mật - QUAN TRỌNG

### **⚠️ Token GitHub Đã Bị Expose**

**Vấn đề:** GitHub token của bạn đã được lưu trong git remote URL:
```
origin: https://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@github.com/...
```

**Rủi ro:**
- Token có thể bị lộ nếu ai đó xem git config
- Token có thể bị lộ trong git history
- Token có thể bị lộ trong logs

**Giải pháp ngay lập tức:**

1. **Revoke token cũ trên GitHub:**
   - Vào: https://github.com/settings/tokens
   - Tìm token `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`
   - Click "Revoke" để vô hiệu hóa

2. **Tạo token mới:**
   - Vào: https://github.com/settings/tokens/new
   - Chọn scopes: `repo` (full control of private repositories)
   - Copy token mới

3. **Update git remote (không lưu token trong URL):**
   ```bash
   git remote set-url origin https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh..git
   ```

4. **Sử dụng Git Credential Manager:**
   ```bash
   # Windows
   git config --global credential.helper wincred
   
   # Hoặc sử dụng token khi push (không lưu trong URL)
   git push origin master
   # Khi hỏi username: lethanhsang188
   # Khi hỏi password: [paste token mới]
   ```

---

## ✅ Files Đã Được Bảo Vệ

### **Files KHÔNG được commit:**
- ✅ `.env` - Chứa API keys, passwords, tokens
- ✅ `*.log` - Log files
- ✅ `cert wazuh/*.pem`, `cert wazuh/*.crt` - Certificates
- ✅ `cert thehive/*.pem`, `cert thehive/*.crt` - Certificates
- ✅ `state/cursor.json` - State files
- ✅ `n8n_data/` - n8n data

### **Files ĐƯỢC commit (an toàn):**
- ✅ `env.template` - Template không có real keys
- ✅ Source code
- ✅ Documentation
- ✅ Configuration templates

---

## 📋 Checklist Trước Khi Push

- [x] .env không được commit
- [x] Certificates không được commit
- [x] Log files không được commit
- [x] API keys không có trong code
- [x] Passwords không có trong code
- [ ] Token GitHub đã được revoke và thay thế
- [ ] Git remote URL không chứa token

---

## 🔧 Đặt Repository Public

**Cách đặt repository public trên GitHub:**

1. Vào: https://github.com/lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh.
2. Click "Settings" (tab trên cùng)
3. Scroll xuống phần "Danger Zone"
4. Click "Change visibility"
5. Chọn "Make public"
6. Xác nhận

**Hoặc qua GitHub CLI:**
```bash
gh repo edit lethanhsang188/-AI-Powered-Alert-Prioritization-for-Wazuh. --visibility public
```

---

## 📝 Commit Summary

**98 files changed:**
- Added: Supply chain attack detection
- Added: CSRF detection (Tier 3 + attack type normalizer)
- Added: Attack type normalization
- Added: Source campaign correlation
- Fixed: Field filtering for CSRF and other attacks
- Updated: Heuristic scoring with attack type bonus
- Updated: Telegram notifications with supply chain warnings
- Updated: SOC implementation guide

**Files excluded:**
- `.env` - Protected by .gitignore ✅

---

## 🎯 Next Steps

1. **Revoke token cũ ngay lập tức** ⚠️
2. **Tạo token mới**
3. **Update git remote** (không lưu token trong URL)
4. **Đặt repository public** (nếu muốn)
5. **Verify .env không có trong repository:**
   ```bash
   git ls-files | findstr ".env"
   # Không nên có .env trong output
   ```

---

**Status:** ✅ Code đã được push, nhưng cần revoke token cũ ngay!

