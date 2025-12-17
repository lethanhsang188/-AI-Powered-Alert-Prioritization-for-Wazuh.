#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script để sửa vấn đề false negative với brute force attacks.

Vấn đề: Alerts "Logon Failure" có rule.level = 5, nhưng WAZUH_MIN_LEVEL = 7
→ Tất cả alerts bị bỏ qua (false negative)

Giải pháp: Giảm WAZUH_MIN_LEVEL xuống 5 để bắt được logon failures.
"""
import sys
import os
import io

# Fix encoding for Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add project root to path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from src.common.config import WAZUH_MIN_LEVEL

def print_section(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def check_current_config():
    """Check current WAZUH_MIN_LEVEL configuration."""
    print_section("KIỂM TRA CẤU HÌNH HIỆN TẠI")
    
    print(f"\n📊 WAZUH_MIN_LEVEL hiện tại: {WAZUH_MIN_LEVEL}")
    
    if WAZUH_MIN_LEVEL >= 7:
        print("\n⚠️  VẤN ĐỀ PHÁT HIỆN:")
        print("   - Alerts 'Logon Failure' có rule.level = 5")
        print(f"   - WAZUH_MIN_LEVEL = {WAZUH_MIN_LEVEL} (chỉ lấy level >= {WAZUH_MIN_LEVEL})")
        print("   - → TẤT CẢ alerts bị BỎ QUA (false negative)")
        return False
    else:
        print("\n✅ CẤU HÌNH ĐÚNG:")
        print(f"   - WAZUH_MIN_LEVEL = {WAZUH_MIN_LEVEL}")
        print("   - Sẽ bắt được alerts 'Logon Failure' (level 5)")
        return True

def suggest_fix():
    """Suggest fix for the issue."""
    print_section("GIẢI PHÁP")
    
    print("📝 Có 2 cách sửa:")
    print("\n1. SỬA FILE .env (Khuyến nghị):")
    print("   - Mở file .env (hoặc tạo từ env.template)")
    print("   - Sửa dòng: WAZUH_MIN_LEVEL=5")
    print("   - Restart pipeline")
    
    print("\n2. SỬA TRỰC TIẾP (Nếu không có file .env):")
    print("   - Sửa file: src/common/config.py")
    print("   - Dòng 59: WAZUH_MIN_LEVEL = get_env_int('WAZUH_MIN_LEVEL', 5)")
    print("   - Restart pipeline")
    
    print("\n⚠️  LƯU Ý:")
    print("   - Giảm WAZUH_MIN_LEVEL xuống 5 sẽ xử lý nhiều alerts hơn")
    print("   - Có thể có noise (alerts không quan trọng)")
    print("   - Nhưng sẽ bắt được brute force attacks sớm hơn")

def check_env_file():
    """Check if .env file exists."""
    env_path = os.path.join(base_dir, ".env")
    template_path = os.path.join(base_dir, "env.template")
    
    if os.path.exists(env_path):
        print_section("FILE .env ĐÃ TỒN TẠI")
        print(f"\n📄 File: {env_path}")
        
        # Read current value
        with open(env_path, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'WAZUH_MIN_LEVEL' in content:
                for line in content.split('\n'):
                    if line.strip().startswith('WAZUH_MIN_LEVEL'):
                        print(f"   {line.strip()}")
                        break
        
        print("\n💡 Để sửa:")
        print(f"   1. Mở file: {env_path}")
        print("   2. Tìm dòng: WAZUH_MIN_LEVEL=7")
        print("   3. Sửa thành: WAZUH_MIN_LEVEL=5")
        print("   4. Lưu file")
        print("   5. Restart pipeline")
        return env_path
    else:
        print_section("FILE .env CHƯA TỒN TẠI")
        print(f"\n📄 File .env không tồn tại")
        print(f"📄 File template: {template_path}")
        
        if os.path.exists(template_path):
            print("\n💡 Để tạo file .env:")
            print(f"   1. Copy file: {template_path}")
            print(f"   2. Đổi tên thành: .env")
            print("   3. Sửa dòng: WAZUH_MIN_LEVEL=5")
            print("   4. Restart pipeline")
        
        return None

def create_env_file():
    """Create .env file from template with WAZUH_MIN_LEVEL=5."""
    env_path = os.path.join(base_dir, ".env")
    template_path = os.path.join(base_dir, "env.template")
    
    if os.path.exists(env_path):
        print(f"\n⚠️  File .env đã tồn tại: {env_path}")
        print("   Không tạo file mới. Vui lòng sửa thủ công.")
        return False
    
    if not os.path.exists(template_path):
        print(f"\n❌ Không tìm thấy file template: {template_path}")
        return False
    
    # Read template
    with open(template_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace WAZUH_MIN_LEVEL
    lines = content.split('\n')
    new_lines = []
    for line in lines:
        if line.strip().startswith('WAZUH_MIN_LEVEL'):
            new_lines.append('WAZUH_MIN_LEVEL=5  # Changed from 7 to catch logon failures (level 5)')
        else:
            new_lines.append(line)
    
    # Write .env file
    with open(env_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))
    
    print(f"\n✅ Đã tạo file .env: {env_path}")
    print("   WAZUH_MIN_LEVEL đã được set = 5")
    print("\n💡 Bước tiếp theo:")
    print("   1. Kiểm tra file .env (có thể cần sửa các config khác)")
    print("   2. Restart pipeline: py -3 bin/run_pipeline.py")
    
    return True

def main():
    """Main function."""
    print_section("🔧 SỬA VẤN ĐỀ FALSE NEGATIVE - BRUTE FORCE DETECTION")
    
    # Check current config
    is_ok = check_current_config()
    
    if is_ok:
        print("\n✅ Cấu hình đã đúng! Không cần sửa.")
        return
    
    # Suggest fix
    suggest_fix()
    
    # Check env file
    env_path = check_env_file()
    
    # Ask if user wants to create .env file
    print_section("TẠO FILE .env TỰ ĐỘNG")
    print("\n❓ Bạn có muốn tạo file .env từ template với WAZUH_MIN_LEVEL=5?")
    print("   (Nhấn Enter để tạo, hoặc Ctrl+C để hủy)")
    
    try:
        input()
        create_env_file()
    except KeyboardInterrupt:
        print("\n\n❌ Đã hủy.")
        print("\n💡 Bạn có thể tự tạo file .env:")
        print("   1. Copy env.template thành .env")
        print("   2. Sửa WAZUH_MIN_LEVEL=5")
        print("   3. Restart pipeline")

if __name__ == "__main__":
    main()


