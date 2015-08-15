from base64 import b64encode, b64decode
from encodings.hex_codec import hex_decode, hex_encode
import unittest
import string

def hexstring_to_b64(hex_string):
    binary_string = hex_decode(hex_string)[0]
    return b64encode(binary_string)

def xor_fixed_length_buffers(buffer1, buffer2):
    if len(buffer1) != len(buffer2):
        raise ValueError("Buffers are not of the same length")

    result = ""
    for i in range(0, len(buffer1)):
        result = result + chr(ord(buffer1[i]) ^ ord(buffer2[i]))
        
    return result

def english_score(plaintext):
    plaintext = plaintext.lower()
    score = 0

    common_chars = ('t', 'a', 'o', 'i', 'n', ' ')
    for char in plaintext:
        if char == 'e':
            score += 2
        elif char in common_chars:
            score += 1
        elif char not in string.printable:
            score = 0
            break

    return score

def find_single_byte_cipher_key(ciphertext):
    guess_results = {}
    for char in range(0x00, 0xFF):
        plaintext = xor_fixed_length_buffers(ciphertext, chr(char)*len(ciphertext))
        score = english_score(plaintext)
        
        guess_results[chr(char)] = score

    sorted_list = sorted(guess_results, key=lambda(k):guess_results[k], reverse=True)

    return sorted_list[0]

def expand_rotating_key(base, key_length):
    result = ""

    i = 0
    while len(result) < key_length:
        result += base[i]
        i += 1
        if i == len(base):
            i = 0

    return result

def hamming_distance(first, second):
    if len(first) != len(second):
        raise ValueError('The strings must have the same length.')

    distance = 0

    for i in range(0, len(first)):
        difference = ord(first[i]) ^ ord(second[i])
        for bit in bin(difference)[2:]:
            if bit == '1':
                distance += 1

    return distance

def guess_rotating_keysize(content, minimum, maximum):
    best_result = 1e6 # arbitrary number to make first run the best result
    best_size   = 0

    for keysize in range(minimum, maximum):
        distance_sum = 0

        for i in range(0, int(len(content)/keysize) - 1, 2):
            first_block  = content[i*keysize:(i+1)*keysize]
            second_block = content[(i+1)*keysize:(i+2)*keysize]

            distance_sum += hamming_distance(first_block, second_block)

        average_distance = distance_sum / (int(len(content)/keysize)/2 - 1)

        if average_distance/keysize < best_result:
            best_result = average_distance/keysize
            best_size = keysize

    return best_size

def transpose_blocks(blocked_contents, key_size):
    transpose_blocks = []

    for column in range(0, key_size):
        transpose_blocks.append("")

        for block in blocked_contents:
            while len(block) != key_size:
                block += chr(0x00) # null padding
            transpose_blocks[column] += block[column]

    return transpose_blocks

def block_contents(content, block_size):
    blocked_contents = []
    for i in range(0, len(content), block_size):
        block = content[i:i+block_size]
        blocked_contents.append(block)
    return blocked_contents

class Set1(unittest.TestCase):
    def testHexConvert(self):
        self.assertEqual(
            'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t', 
            hexstring_to_b64(
                '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
            )
        )
    def testXorBuffers(self):
        self.assertEqual(
                "746865206b696420646f6e277420706c6179", 
            hex_encode(xor_fixed_length_buffers(
                hex_decode("1c0111001f010100061a024b53535009181c")[0],
                hex_decode("686974207468652062756c6c277320657965")[0]
            ))[0]
        )
    def testSingleByteXorDecryption(self):
        ciphertext = hex_decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0]
        guess = find_single_byte_cipher_key(ciphertext)
        plaintext = xor_fixed_length_buffers(ciphertext, guess*len(ciphertext)) 

        self.assertEqual("Cooking MC's like a pound of bacon", plaintext)

    def testDetectSingleByteXorCipher(self):
        with open("4.txt", "rb") as file_handle:
            results = {}
            for ciphertext_encoded in file_handle:
                ciphertext = hex_decode(ciphertext_encoded.rstrip())[0]
                key_guess = find_single_byte_cipher_key(ciphertext)
                plaintext = xor_fixed_length_buffers(ciphertext, key_guess*len(ciphertext))
                score = english_score(plaintext)

                results[plaintext] = { "score" : score, "key" : key_guess }

            sorted_list = sorted(results, key=lambda(k): results[k]["score"], reverse=True)

            self.assertEqual("Now that the party is jumping\n", sorted_list[0])

    def testRotatingKey(self):
        plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        key = expand_rotating_key("ICE", len(plain_text))

        ciphertext = hex_encode(xor_fixed_length_buffers(plain_text, key))[0]

        self.assertEqual(ciphertext, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

    def testHammingDistance(self):
        self.assertEqual(hamming_distance("this is a test", "wokka wokka!!!"), 37)

#    def testGuessRotatingKeysize(self):
#        plaintext = "I am the very model of a modern major-general, I've information vegetable animal and mineral."
#        rotating_key = "abc"
#
#        key = expand_rotating_key(rotating_key, len(plaintext))
#        ciphertext = xor_fixed_length_buffers(plaintext, key)
#        keysize_guess = guess_rotating_keysize(ciphertext, 2, 10)
#
#        self.assertEqual(keysize_guess, len(rotating_key))

    def testFullDecryptRepeatingXOR(self):
        with open("6.txt", "rb") as file_handle:
            contents = b64decode(file_handle.read())

            best_size = guess_rotating_keysize(contents, 2, 40)

            blocked_contents = block_contents(contents, best_size)
            transposed_blocks = transpose_blocks(blocked_contents, best_size)
            
            full_key = ""
            for ciphertext in transposed_blocks:
                guess     = find_single_byte_cipher_key(ciphertext)
                full_key += guess

            decrypted_contents = ""
            for block in blocked_contents:
                decrypted_contents += xor_fixed_length_buffers(block, expand_rotating_key(full_key, len(block)))

            with open("6.plain.txt", "rb") as plain_file:
                self.assertEqual(plain_file.read(), decrypted_contents)

if __name__ == '__main__':
    unittest.main()

