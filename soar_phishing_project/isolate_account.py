def isolate_account(user_email, simulate=True):
    if simulate:
        print(f"[SIMULATION] Account {user_email} DISABLED.")
        print("[SIMULATION] Password reset triggered.")
        print("[SIMULATION] MFA enforced.")
    else:
        pass

if __name__ == "__main__":
    isolate_account("victim@example.com")
