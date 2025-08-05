def run_user_code(user_input):
    eval(user_input)  # Dangerous: unsanitized input to eval

if __name__ == "__main__":
    user_input = input("Enter code to run: ")
    run_user_code(user_input)
