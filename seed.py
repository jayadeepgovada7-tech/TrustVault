import os
from pathlib import Path
from app.config import Config
from app.database import init_db, seed_db

def main():
    print(f"[*] Initializing TrustVault Database at: {Config.DATABASE_PATH}")
    db_file = Path(Config.DATABASE_PATH)
    if db_file.exists():
        print(f"[!] Database file exists. Running schema updates and seed verification...")
    
    init_db()
    seed_db()
    print("[+] Database schema successfully verified and seeded!")
    print("\nDevelopment Seed Accounts:")
    print("----------------------------------------------------------------------")
    print("Role: Administrator")
    print("  Email:    admin@trustvault.local")
    print("  Password: Admin@TrustVault2026!")
    print("----------------------------------------------------------------------")
    print("Role: Document Owner")
    print("  Email:    owner@trustvault.local")
    print("  Password: Owner@TrustVault2026!")
    print("----------------------------------------------------------------------")
    print("Role: Viewer")
    print("  Email:    viewer@trustvault.local")
    print("  Password: Viewer@TrustVault2026!")
    print("----------------------------------------------------------------------")
    print("Role: Secondary Owner (for IDOR / boundary testing)")
    print("  Email:    otherowner@trustvault.local")
    print("  Password: Other@TrustVault2026!")
    print("----------------------------------------------------------------------")

if __name__ == '__main__':
    main()
