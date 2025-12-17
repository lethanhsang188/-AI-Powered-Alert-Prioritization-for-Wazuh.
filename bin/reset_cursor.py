#!/usr/bin/env python3
"""Reset cursor to fetch alerts from beginning or recent time window."""
import sys
import os
import json
from datetime import datetime, timedelta

# Add project root to path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

from src.common.config import CURSOR_PATH

def reset_cursor(keep_recent_hours: int = 24):
    """
    Reset cursor file.
    
    Args:
        keep_recent_hours: If > 0, set cursor to N hours ago (to avoid processing very old alerts)
                          If 0, delete cursor completely (fetch from beginning)
    """
    if keep_recent_hours > 0:
        # Set cursor to N hours ago
        cutoff_time = datetime.utcnow() - timedelta(hours=keep_recent_hours)
        cutoff_iso = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        
        cursor_data = {
            "timestamp": cutoff_iso,
            "note": f"Reset to {keep_recent_hours} hours ago"
        }
        
        try:
            os.makedirs(os.path.dirname(CURSOR_PATH), exist_ok=True)
            with open(CURSOR_PATH, "w") as f:
                json.dump(cursor_data, f, indent=2)
            print(f"✅ Cursor reset to {keep_recent_hours} hours ago: {cutoff_iso}")
            print(f"   Pipeline will fetch alerts from this timestamp onwards")
        except Exception as e:
            print(f"❌ Failed to reset cursor: {e}")
            return False
    else:
        # Delete cursor completely
        try:
            if os.path.exists(CURSOR_PATH):
                os.remove(CURSOR_PATH)
                print(f"✅ Cursor file deleted: {CURSOR_PATH}")
                print(f"   Pipeline will fetch alerts from beginning")
            else:
                print(f"ℹ️  Cursor file does not exist: {CURSOR_PATH}")
        except Exception as e:
            print(f"❌ Failed to delete cursor: {e}")
            return False
    
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Reset Wazuh alert cursor")
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Set cursor to N hours ago (default: 24). Use 0 to delete cursor completely."
    )
    
    args = parser.parse_args()
    
    print(f"🔄 Resetting cursor...")
    print(f"   Cursor path: {CURSOR_PATH}")
    
    if args.hours == 0:
        print(f"   Mode: Delete cursor (fetch from beginning)")
    else:
        print(f"   Mode: Set cursor to {args.hours} hours ago")
    
    success = reset_cursor(args.hours)
    
    if success:
        print(f"\n✅ Done! You can now run pipeline:")
        print(f"   py -3 bin\\run_pipeline.py")
    else:
        print(f"\n❌ Failed to reset cursor")
        sys.exit(1)

