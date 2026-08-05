import os
import sys
import threading
import time
import webbrowser
import multiprocessing
import uvicorn

if getattr(sys, "frozen", False):
    bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    os.chdir(bundle_dir)
    sys.path.insert(0, bundle_dir)

from app.main import app


def open_browser():
    time.sleep(1.5)
    webbrowser.open("http://127.0.0.1:8787")


if __name__ == "__main__":
    multiprocessing.freeze_support()
    print("=" * 60)
    print(" ChatGPT Account Checker")
    print(" Server dang chay tai: http://127.0.0.1:8787")
    print(" Trinh duyet se tu dong mo sau vai giay...")
    print(" (Vui long khong dong cua so nay khi dang su dung)")
    print("=" * 60)

    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8787, log_level="info")
