import os

def run_user_code(user_input):
    eval(user_input)

if __name__ == "__main__":
    file_path = "untrusted_input.txt"
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            user_input = f.read()
        print("Running code from file...")
        run_user_code(user_input)
    else:
        print("untrusted_input.txt not found. Exiting.")