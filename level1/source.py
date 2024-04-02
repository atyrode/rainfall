import os

# The never called run function
def run():
    print "Good... Wait what ?"
    os.execl("/bin/sh", "sh") # Executes the shell

# The vulnerable main function.
# If the buffer is overflowed, the return address of main could be overwritten
# and point to run

# Of course this can't happen in Python, but this is what could happen in C
def main():
    buffer = [0] * 64 # Creates a buffer of 64 bytes
    user_input = input() # Reads the user input
    buffer.append(user_input) # Appends it to the buffer

if __name__ == '__main__':
    main()