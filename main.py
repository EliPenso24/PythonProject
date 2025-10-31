"""
Eli Penso, 17/10/25,
Encryption and Decryption of messages:
If the parameter is encrypt then the program will encrypt the code it received from the user.
And save the encrypted file (encrypted_msg.txt) in the directory from which the program was run.
If the parameter is decrypt then the program will read the file with the encrypted code and print a message after decryption.
Error handling:
Invalid input or missing files are handled with appropriate error messages.
Assertions are used to ensure that all values exist in the decryption table and that the code works correctly.
Empty messages are handled (saving and decrypting empty files).
Logging:
All key actions and errors are logged to 'logs/program.log'.
"""
import os
import logging
import sys


def createlogs():
    os.makedirs("logs", exist_ok=True)
    logging.basicConfig(filename='logs/program.log', filemode='w', level=logging.INFO)
    format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


# data structures for encryption and decryption
def createdata():
    ENCODE_DATA_STRUCTURE = {
        'g': 18, 'h': 19, 'i': 30, 'j': 31, 'k': 32, 'l': 33, 'm': 34, 'n': 35,
        'o': 36, 'p': 37, 'q': 38, 'r': 39, 's': 90, 't': 91, 'u': 92, 'v': 93,
        '!': 102, '-': 103, 'A': 56, 'B': 57, 'C': 58, 'D': 59, 'E': 40, 'F': 41,
        'G': 42, 'H': 43, 'I': 44, 'J': 45, 'K': 46, 'L': 47, 'M': 48, 'N': 49,
        'O': 60, 'P': 61, 'Q': 62, 'R': 63, 'S': 64, 'T': 65, 'U': 66, 'V': 67,
        'W': 68, 'X': 69, 'Y': 10, 'Z': 11, 'a': 12, 'b': 13, 'c': 14, 'd': 15,
        'e': 16, 'f': 17, 'w': 94, 'x': 95, 'y': 96, 'z': 97, ' ': 98, ',': 99,
        '.': 100, "'": 101
    }
    DECODE_DATA_STRUCTURE = {a: b for b, a in ENCODE_DATA_STRUCTURE.items()}

def read():
    """
    This function reads encrypted data from a file.
    :return: the string content of the file.
    """
    logging.info('Reading data from file')
    try:
        with open("encrypted_msg.txt", "r") as file:
            info = file.read()
    except FileNotFoundError:
        logging.error('File not found')
        print("Error: Encrypted file not found.")
        sys.exit(1)
    return info


def decrypt(info): # פונקציית הפענוח המטפלת בשגיאות
    """
    This function decrypts a message and checks that the file from which it gets
    its information exists and that all the chars are in the decode data structure.
    :param info: the string content of the file.
    :return: prints decrypted message.
    """
    logging.info('Decrypting data from file')
    if not info:
        print('')
        logging.info('empty file decrypted')
        sys.exit(0)

    decrypted_info = []
    for value_str in info.split(","):
        try:
            value = int(value_str)
        except ValueError:
            logging.error('Invalid data format')
            print(f"error: Invalid data in encrypted file: '{value_str}'")
            sys.exit(1)

        assert value in DECODE_DATA_STRUCTURE, f"לא ניתן לפענח את {value_str}"
        decrypted_info.append(DECODE_DATA_STRUCTURE[value])
    decrypted_message = "".join(decrypted_info) # יוצר הודעה מהתווים המפוענחים
    logging.info('decrypted message')
    return decrypted_message

def validate(message):
    """
    This function validates that the message is valid and partially encrypts it.
    :param message: the message to be validated.
    :return: the message after being encrypted and put into a list.
    """
    logging.info('Validating message')
    try:
        encrypted_message = ",".join(str(ENCODE_DATA_STRUCTURE[ch]) for ch in message)
    except KeyError:
        logging.error('Invalid data format')
        invalid_chars = [ch for ch in message if ch not in ENCODE_DATA_STRUCTURE]
        print(f"Error: התווים הבאים אינם נתמכים: {invalid_chars}")
        sys.exit(1)
    logging.info('Encrypted message')
    return encrypted_message

def encrypt(encrypted_message):
    """
    This function checks that the input is valid and encrypts an input from the user.
    :param encrypted_message: the input to be encrypted.
    :return: create: file with encrypted message.
    """
    logging.info('Encrypting message')
    try:
        with open("encrypted_msg.txt", "w") as file:
            file.write(encrypted_message)
        print("Message encrypted!!!")
    except Exception as a:
        logging.error(f"error writing to fie: {a}")
        print(f"error writing to file: {a}")
        sys.exit(1)
    logging.info('Message encrypted')


def validparameters(action):
    """
    This function checks that the input representing the parameter is valid.
    :param action: the action to be checked.
    :return: print: message if invalid.
    """
    logging.info('validating parameters')
    if action not in ('encrypt', 'decrypt'):
        logging.error('invalid parameter')
        return "Action has to be 'encrypt' or 'decrypt'!!!"
    logging.info('Parameter valid')
    return "Action is valid!!!"

def main():
    """
    This is the main function.
    """
    logging.info('***Main function***\n')
    if len(sys.argv) < 2:
        logging.error('No Parameter entered')
        print("error: You have to provide an action ('encrypt' or 'decrypt').")
        sys.exit(1)
    action = sys.argv[1].lower()
    validation = validparameters(action)
    print(validation)
    if action == 'encrypt':
        message = input("Enter message you want to encrypt: ")
        validation = validate(message)
        encrypt(validation)
    elif action == 'decrypt':
        info = read()
        decrypted_message = decrypt(info)
        print(decrypted_message)
    logging.info('***Main function***\n')

if __name__=='__main__':
    """
    Assertions and running main function
    """
    createlogs()
    createdata()
    main()
    logging.info("***ASSERTIONS***\n")
    assert decrypt('19,30')=='hi'
    assert validate('hi')== "19,30"
    assert validparameters('c') == "Action has to be 'encrypt' or 'decrypt'!!!"
    assert validparameters('encrypt') == "Action is valid!!!"
    assert validparameters('decrypt') == "Action is valid!!!"
    logging.info("***ASSERTIONS***")
