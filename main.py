from database import create_tables
from password_manager import (
    user_exists, create_user, verify_master,
    add_password, get_password, delete_password, list_accounts
)

def prompt(msg: str) -> str:
    return input(msg).strip()

def first_screen():
    print("=== Password Manager ===")
    print("1) Log in")
    print("2) Create new user")
    print("3) Exit")
    choice = prompt("Choose: ")
    return choice

def main_menu():
    print("\n--- Menu ---")
    print("1) Add password")
    print("2) View password")
    print("3) Delete password")
    print("4) List accounts")
    print("5) Logout")
    return prompt("Choose: ")

def run():
    create_tables()

    while True:
        choice = first_screen()
        if choice == "1":
            username = prompt("Username: ")
            master = prompt("Master password: ")
            user_id = verify_master(username, master)
            if not user_id:
                print("❌ Invalid username or master password.\n")
                continue

            print(f"✅ Logged in as {username}")
            # Authenticated session loop
            while True:
                c = main_menu()
                if c == "1":
                    account = prompt("Account name (e.g., 'gmail'): ")
                    pw = prompt("Password to store: ")
                    add_password(user_id, master, account, pw)
                    print("✅ Saved.")
                elif c == "2":
                    account = prompt("Account name to view: ")
                    plain = get_password(user_id, master, account)
                    if plain is None:
                        print("❌ Not found or decryption failed.")
                    else:
                        print(f"🔓 {account} → {plain}")
                elif c == "3":
                    account = prompt("Account name to delete: ")
                    ok = delete_password(user_id, account)
                    print("✅ Deleted." if ok else "❌ Account not found.")
                elif c == "4":
                    rows = list_accounts(user_id)
                    if not rows:
                        print("ℹ️ No accounts yet.")
                    else:
                        print("Accounts:")
                        for _, name in rows:
                            print(f" • {name}")
                elif c == "5":
                    print("🔒 Logged out.\n")
                    break
                else:
                    print("❓ Unknown option.")

        elif choice == "2":
            username = prompt("Choose a username: ")
            if user_exists(username):
                print("⚠️ That username already exists.")
                continue
            master = prompt("Create a master password: ")
            create_user(username, master)
            print("✅ User created. You can log in now.\n")
        elif choice == "3":
            print("Goodbye!")
            return
        else:
            print("❓ Unknown option.\n")

if __name__ == "__main__":
    run()
