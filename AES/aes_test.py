
import AES as aes  # Import AES to test it


def print_separator_short():
    print("----------------------------------------------")


def print_separator_long():
    print("=======================================================================================================================================")


if __name__ == '__main__':
    print_separator_short()
    print("Example of AES encryption and decryption")
    print("128 bit key and message version")
    print_separator_short()


    KEYS = {
        128: ["9ae89de895f5acb2872d23cc1fd7cd2d", "AliHaydar KURBAN"],  # 128-bit keys (16 characters)
        192: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934c", "KeyFor192Bit____LongPartExtra"],  # 192-bit keys (24 characters)
        256: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Another256BitKeyForTestingAES___"]  # 256-bit keys (32 characters)
    }

    TEXTS = ["Two One Nine Two", "This is the text"]


    state = input("Enter perfome encryption or decryption (e/d):")

    if state == "e":
        key_size = int(input("Enter key size: "))
        key = input("Enter key: ")
        text = input("Enter text: ")
    
        print_separator_long()
        main_key = aes.hex_to_hex_array(key) #make array of key
        main_hex = aes.translate_string_into_hex_str(text) #traslate user text to hex array
        round_keys = aes.find_all_round_keys(main_key,key_size) #make all round keys
        
        #encryption
        cypher_hex = aes.encrypt(main_hex, round_keys,key_size)
        cypher_text = aes.hex_array_to_hex_string(cypher_hex)

        print("Key : \'{}\'".format(key))
        print("Message Text : \'{}\'".format(text))
        print("Length of Text :", len(text))
        print("Encrypted Text :", cypher_text)

    elif state == "d":
        key_size = int(input("Enter key size: "))
        key = input("Enter key: ")
        cypher_text = input("Enter cypher text: ")

        print_separator_long()
        main_key = aes.hex_to_hex_array(key) #make array of key
        round_keys = aes.find_all_round_keys(main_key,key_size) #make all round keys
        cypher_hex = aes.hex_to_hex_array(cypher_text)

        #decryption
        plain_hex = aes.decryption(cypher_hex, round_keys,key_size)
        plain_text = aes.translate_hex_into_str(plain_hex)

        print("Key : \'{}\'".format(key))
        print("Cipher Text : \'{}\'".format(cypher_text))
        print("Length of Plain Text :", len(plain_text))
        print("Plain Text : \'{}\'".format(plain_text))

    else:
        print("somthing went wrong")    


    print_separator_long()
