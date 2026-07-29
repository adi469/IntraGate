#!/usr/bin/env python3
"""IntraGate Admin Password Reset Tool

Allows administrators to reset passwords and disable 2FA/TOTP directly
via the command line when locked out.
"""

import sys
import asyncio
import getpass
import argparse
from pathlib import Path

# Add project root to python path to resolve 'app' modules
project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from app.database import AsyncSessionLocal
from app.db_models import AdminUser
from app.admin_auth import _hash_password
from sqlalchemy import select


def parse_args():
    parser = argparse.ArgumentParser(
        description="IntraGate Administrator Credentials Reset Utility"
    )
    parser.add_argument(
        "--username",
        type=str,
        default="admin",
        help="Username of the admin account to reset (default: admin)",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="New password for the admin account (prompts interactively if not provided)",
    )
    parser.add_argument(
        "--disable-totp",
        action="store_true",
        default=True,
        help="Disable Multi-Factor Authentication/TOTP (default: True)",
    )
    return parser.parse_args()


async def reset_credentials(username: str, password_raw: str, disable_totp: bool):
    hashed_pwd = _hash_password(password_raw)

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(AdminUser).where(AdminUser.username == username)
        )
        admin = result.scalar_one_or_none()

        if not admin:
            print(f"Error: Admin account with username '{username}' does not exist.")
            choice = input("Would you like to create this account? (y/N): ").strip().lower()
            if choice == "y":
                admin = AdminUser(
                    username=username,
                    password_hash=hashed_pwd,
                    totp_enabled=False,
                    totp_secret=None
                )
                session.add(admin)
                print(f"Creating new admin account '{username}'...")
            else:
                print("Aborting.")
                return False
        else:
            admin.password_hash = hashed_pwd
            if disable_totp:
                admin.totp_enabled = False
                admin.totp_secret = None
                print(f"Resetting password and disabling 2FA/TOTP for admin '{username}'...")
            else:
                print(f"Resetting password for admin '{username}' (leaving TOTP settings intact)...")
            session.add(admin)

        await session.commit()
        print("Success: Admin credentials updated successfully!")
        return True


def main():
    args = parse_args()
    
    password = args.password
    if not password:
        print(f"--- Resetting credentials for admin account: '{args.username}' ---")
        while True:
            password = getpass.getpass("Enter new password: ")
            if not password:
                print("Password cannot be empty. Try again.")
                continue
            confirm = getpass.getpass("Confirm new password: ")
            if password != confirm:
                print("Passwords do not match. Try again.")
                continue
            break

    try:
        asyncio.run(
            reset_credentials(
                username=args.username,
                password_raw=password,
                disable_totp=args.disable_totp,
            )
        )
    except Exception as e:
        print(f"\nError connecting to database: {e}")
        print("Make sure PostgreSQL is running and environment variables are loaded.")
        sys.exit(1)


if __name__ == "__main__":
    main()
