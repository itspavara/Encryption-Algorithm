import random

def gcd(a, b):
    # Performs the Euclidean algorithm and returns the gcd of a and b.
    while b != 0:
        a, b = b, a % b
    return a

def xgcd(a, b):
    #Performs the extended Euclidean algorithm and returns the gcd, coefficient of a, and coefficient of b.
    x, old_x = 0, 1
    y, old_y = 1, 0

    while b != 0:
        quotient = a // b
        a, b = b, a - quotient * b
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    return a, old_x, old_y

def choose_e(totient):
    #Chooses a random number, 1 < e < totient, and checks whether it is coprime with the totient.
    while True:
        e = random.randrange(2, totient)
        if gcd(e, totient) == 1:
            return e

def choose_keys():
    #Selects two random prime numbers from a list of prime numbers up to 100k.
    #Computes and stores the public and private keys in separate files.
    
    rand1 = random.randint(100, 300)
    rand2 = random.randint(100, 300)

    with open('primes.txt', 'r') as primes:
        lines = primes.read().splitlines()

    prime1 = int(lines[rand1])
    prime2 = int(lines[rand2])

    n = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    e = choose_e(totient)

    gcd, x, y = xgcd(e, totient)
    d = x + totient if x < 0 else x

    with open('public_keys.txt', 'w') as f_public:
        f_public.write(f"{n}\n{e}\n")

    with open('private_keys.txt', 'w') as f_private:
        f_private.write(f"{n}\n{d}\n")

def encrypt(message, file_name='public_keys.txt', block_size=2):
    
    #Encrypts a message by raising each character's ASCII value to the power of e and taking the modulus of n.
    #Returns a string of numbers.
    
    try:
        with open(file_name, 'r') as fo:
            n = int(fo.readline())
            e = int(fo.readline())
    except FileNotFoundError:
        print('That file is not found.')
        return

    encrypted_blocks = []
    ciphertext = 0

    for i, char in enumerate(message):
        if i % block_size == 0 and i != 0:
            encrypted_blocks.append(ciphertext)
            ciphertext = 0
        ciphertext = ciphertext * 1000 + ord(char)

    encrypted_blocks.append(ciphertext)

    encrypted_message = " ".join(str((block**e) % n) for block in encrypted_blocks)
    return encrypted_message


def decrypt(blocks, block_size=2):
    
    #Decrypts a string of numbers by raising each number to the power of d and taking the modulus of n.
    #Returns the message as a string.
    
    with open('private_keys.txt', 'r') as fo:
        n = int(fo.readline())
        d = int(fo.readline())

    int_blocks = [int(s) for s in blocks.split(' ')]
    message = ""

    for block in int_blocks:
        block = (block**d) % n
        tmp = ""
        for _ in range(block_size):
            tmp = chr(block % 1000) + tmp
            block //= 1000
        message += tmp

    return message

