import RSA as rsa

def print_separator_short():
    print("----------------------------------------------")


def print_separator_long():
    print("=======================================================================================================================================")


if __name__ == '__main__':
    print_separator_short()
    print("Example of RAS encryption and decryption")
    print_separator_short()


    if input('Do you want to generate new public and private keys? (y or n) ') == 'y':
        rsa.choose_keys()

    instruction = input('Would you like to encrypt or decrypt? (Enter e or d): ')
    if instruction == 'e':
        message = input('What would you like to encrypt?\n')
        if input('Do you want to encrypt using your own public key? (y or n) ') == 'y':
            print('Encrypting...')
            print(rsa.encrypt(message))
        else:
            file_option = input('Enter the file name that stores the public key: ')
            print('Encrypting...')
            print(rsa.encrypt(message, file_option))
    elif instruction == 'd':
        message = input('What would you like to decrypt?\n')
        print('Decryption...')
        print(rsa.decrypt(message))
    else:
        print('That is not a proper instruction.')