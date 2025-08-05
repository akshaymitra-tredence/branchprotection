import sys

def run_user_code(user_input):
    eval(user_input)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_input = sys.argv[1]
        run_user_code(user_input)
    else:
        print("Please provide a command-line argument.")