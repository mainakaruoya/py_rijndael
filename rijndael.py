# An implementation of the AES algorithm - Rijndael - that hopes to be faithful to the FIPS 197 standard
import os  # To generate the key for use by the AES algorithm.
import argparse  # To accept CLI arguments
import operator  # For the XOR and bitwise left shift functions, more or less
# colorama is used to color the key output printed on the terminal - the original message, its ciphertext, and the decrypted ciphertext
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

colorama_init()

# S-Box constants in hexadecimal format
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-Box constants in hexadecimal format
S_BOX_INVERSE = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# The round constants for generating the key schedule in hex format
ROUND_CONSTANTS_KEYEXPANSION = [
    [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00], [0x10, 0x00, 0x00, 0x00], [
        0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00], [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
]


# The parser that will handle the arguments from command-line that we will pass
parser = argparse.ArgumentParser(
    description="This is a CLI-based implementation of AES. Takes a plaintext message, as well as the key size (128, 192, or 256 bits), and then encrypts and decrypts the message, printing out the resulting decrypted plaintext message."
)

parser.add_argument("-m", "--message", metavar="<plaintext>", type=str,
                          help="The message to encrypt and decrypt.", required=True)

parser.add_argument("-l", "--length", metavar="<key length>", type=int, choices=[
                    128, 192, 256], help="Key length for the AES function. The possible values that can be selected are 128, 192, or 256 bits", required=True)


# Step 1b: Pad the string. It needs to be at least 16 bytes long. It has been easier, for me, to pad the string *before* partitioning.
# This might not be exactly like PKCS#7 padding
def padInputString(inputString: str) -> bytes:
    if len(inputString) % 16 != 0:
        inputString += f"{(16 - (len(inputString) % 16))}" * (16 - (len(inputString) % 16))

    # Convert the input message into a set of UTF-8 bytes
    return inputString.encode("utf-8")


# This function splits a list into 16-byte blocks, which I am calling 'chunks'. This function isn't specified in the standard, but makes life easier
# It is called on the key schedule and the plaintext, and makes the rijndaelForwardCipher() function easier to work with, as it will now just work with 16-byte blocks directly
def chunkedList(listOfElements: list) -> list:
    listToReturn = []

    for index in range(int(len(listOfElements) / 4)):
        listToReturn.append(
            [listOfElements[0 + (4 * index)], listOfElements[1 + (4 * index)],
             listOfElements[2 + (4 * index)], listOfElements[3 + (4 * index)]]
        )

    return listToReturn


# Step 2: Split the plaintext message that the user has given to the program into chunks of 4 bytes
def partitionInputString(inputString: bytes) -> list[int]:

    partitionedString = []

    print("---INPUT MESSAGE PARTITIONING---\n")

    for index in range(int(len(inputString) / 4)):
        partitionedString.append(
            [inputString[0 + (4 * index)], inputString[1 + (4 * index)],
             inputString[2 + (4 * index)], inputString[3 + (4 * index)]]
        )

    return partitionedString


# Step 3: Generate the key to be used by the algorithm - use the keyLength as determinant for key length
# For cryptographically secure random bits, we use the os.urandom() function
def generateKey(selectedKeySize: int) -> tuple[int, bytes]:
    if selectedKeySize == 128:
        return 10, os.urandom(int(selectedKeySize / 8))
    if selectedKeySize == 192:
        return 12, os.urandom(int(selectedKeySize / 8))
    if selectedKeySize == 256:
        return 14, os.urandom(int(selectedKeySize / 8))


# This SBox() function is used by both the key expansion phase and the forward cipher function
def sBoxFunction(entry: int) -> int:
    return S_BOX[entry]


# Step 4: Key expansion: Three parts
# Function 4.1: SubWord() function - used by the key expansion function
def subWord(word: int) -> int:
    return [sBoxFunction(word[0]), sBoxFunction(word[1]), sBoxFunction(word[2]), sBoxFunction(word[3])]

# Function 4.2: RotWord() function - used by the key expansion function
def rotWord(word: int) -> int:
    return [word[1], word[2], word[3], word[0]]

# Function 4.3: Key expansion proper - in the AES FIPS document, the expanded key is called the key schedule
def generateKeySchedule(rounds: int, initialKey: bytes) -> tuple[int, list[int]]:

    # List to hold the expanded key, as a list of lists, with each sub-list holding 4 bytes
    expandedKey = []
    count = 0  # Counter for round expansion
    keyLengthinWords = int(len(initialKey) / 4)

    print("---KEY SCHEDULE GENERATION---\n")

    # 4 is the number of words (i.e., 4-byte groups); this produces lists with 4 values each, taken from the key itself
    while count <= keyLengthinWords - 1:
        expandedKey.append(
            [initialKey[0 + (4 * count)], initialKey[1 + (4 * count)],
             initialKey[2 + (4 * count)], initialKey[3 + (4 * count)]]
        )
        count += 1

    # This section produces the rest of the key schedule, using some round constants as well as other words currently in the key schedule
    while (count <= ((4 * rounds) + 3)):

        # The reason for dividing len(initialKey) by 4 is because in the standard, that value, which is labelled Nk, is the number of words (4-byte groups) present in the key
        # We subtract 1 from the ROUND_CONSTANTS_KEYEXPANSION index because our round constants are indexed from 0, whilst in the standard the indices start at 1
        if (count % keyLengthinWords) == 0:
            expandedKey.append(
                [(a ^ b) for a, b in zip(subWord(rotWord(expandedKey[(count - 1)])),
                                         ROUND_CONSTANTS_KEYEXPANSION[int(count / keyLengthinWords) - 1])]
            )

        elif keyLengthinWords > 6 and (count % keyLengthinWords == 4):
            expandedKey.append(subWord(expandedKey[(count - 1)]))

        else:
            temp = [operator.xor(a, b) for (a, b) in zip(
                expandedKey[count - keyLengthinWords], expandedKey[(count - 1)])]
            expandedKey.append(temp)

        count += 1

    return rounds, expandedKey


# Step 5: The forward cipher - the one that 'encrypts' our plaintext
# Depends on other functions created here, as well as the sBoxFunction() defined earlier
# Function 5.1: AddRoundKey()
def addRoundKey(plaintextBlock: list, roundKey: list) -> list:
    roundKeyAdded = []

    for section in range(len(roundKey)):
        xorOperation = [operator.xor(a, b) for a, b in zip(
            plaintextBlock[section], roundKey[section])]
        roundKeyAdded.append(xorOperation)

    return roundKeyAdded


# Function 5.2: SubBytes()
# This is added to call the sBoxFunction() on each of the words within the rijndaelForwardCipher()
def subBytes(valuesToSubstitute: list) -> list:
    substitutedValues = []

    for item in range(len(valuesToSubstitute)):
        substitutedValues.append(
            list(map(sBoxFunction, valuesToSubstitute[item]))
        )

    return substitutedValues

# Function 5.3: ShiftRows()
# Probably the simplest way - hardcoding indices for each value, and returning the list directly as opposed to assigning it to a variable.
def shiftRows(valuesToShift: list) -> list:
    return [
        [valuesToShift[0][0], valuesToShift[1][1], valuesToShift[2][2], valuesToShift[3][3]],
        [valuesToShift[1][0], valuesToShift[2][1], valuesToShift[3][2], valuesToShift[0][3]],
        [valuesToShift[2][0], valuesToShift[3][1], valuesToShift[0][2], valuesToShift[1][3]],
        [valuesToShift[3][0], valuesToShift[0][1], valuesToShift[1][2], valuesToShift[2][3]]
    ]

# Function 5.4: MixColumns()
# Function 5.4.1: xTimes() and its extension, xTimesGreaterThanTwo(), the precursors to mixColumns(). Uses multiplication in a Galois (finite) field, which is slightly different from normal multiplication.
# Function 5.4.1.1: xTimes()
def xTimes(listEntry: int, multiplier: int) -> bytes:

    if multiplier == 2 and listEntry & 0x80:
        byte = listEntry << 1
        byte ^= 0x1b
        byte &= 0xff
        return byte
    elif multiplier == 2:
        byte = listEntry << 1
        byte &= 0xff
        return byte
    else:
        return listEntry

# Function 5.4.1.2: xTimesGreaterThanTwo(), the variant of xTimes() that handles values greater than 2
def xTimesGreaterThanTwo(listEntry: int, multiplier: int) -> int:
    if multiplier == 3:  # {03}
        return listEntry ^ xTimes(listEntry, 2)

    if multiplier == 8:  # {08}
        return xTimes(xTimes(xTimes(listEntry, 2), 2), 2)

    if multiplier == 9:  # {09}
        return listEntry ^ xTimesGreaterThanTwo(listEntry, 8)

    if multiplier == 11:  # {0b}
        return (xTimesGreaterThanTwo(listEntry, 8)) ^ xTimes(listEntry, 2) ^ listEntry

    if multiplier == 13:  # {0d}
        return xTimesGreaterThanTwo(listEntry, 8) ^ xTimes((xTimes(listEntry, 2)), 2) ^ listEntry

    if multiplier == 14:  # {0e}
        return xTimesGreaterThanTwo(listEntry, 8) ^ xTimes((xTimes(listEntry, 2)), 2) ^ xTimes(listEntry, 2)

    return listEntry

# Function 5.4.2: MixColumns() proper
def mixColumns(columns: list) -> list:
    mixedColumns = []

    for index in range(len(columns)):
        mixedColumns.append(
            [xTimes(columns[index][0], 2) ^ xTimesGreaterThanTwo(columns[index][1], 3) ^ columns[index][2] ^ columns[index][3],
             columns[index][0] ^ xTimes(columns[index][1], 2) ^ xTimesGreaterThanTwo(columns[index][2], 3) ^ columns[index][3],
             columns[index][0] ^ columns[index][1] ^ xTimes(columns[index][2], 2) ^ xTimesGreaterThanTwo(columns[index][3], 3),
             xTimesGreaterThanTwo(columns[index][0], 3) ^ columns[index][1] ^ columns[index][2] ^ xTimes(columns[index][3], 2)
             ]
        )

    return mixedColumns

# Function 5.5: The forward cipher proper
def rijndaelForwardCipher(plaintext: bytes, numberOfRounds: int, keySchedule: list) -> list[list[list[int]]]:
    encryptedPlaintext = []

    print("---ENCRYPTION---")

    # We iterate through each block, and apply the entirety of the key to it, at different intervals.
    for block in plaintext:

        initializedState = addRoundKey(block, keySchedule[0])

        for iteration in range(1, numberOfRounds):
            subBytesState = subBytes(initializedState)
            shiftRowsState = shiftRows(subBytesState)
            mixColumnsState = mixColumns(shiftRowsState)
            initializedState = addRoundKey(
                mixColumnsState, keySchedule[iteration])

        finalSubBytesState = subBytes(initializedState)
        finalShiftRowsState = shiftRows(finalSubBytesState)
        finalAddRoundKeyState = addRoundKey(
            finalShiftRowsState, keySchedule[numberOfRounds])

        encryptedPlaintext.append(finalAddRoundKeyState)

    return encryptedPlaintext


# Step 6: The reverse cipher - the one that 'decrypts' our ciphertext
# Depends on other functions created here, as well as the inverseSBoxFunction() above.
# Note: the inverse cipher uses the same addRoundKey() as the forward cipher - an XOR is an inverse of itself, that's why
# Function 6.1: InvShiftRows()
def inverseShiftRows(valuesToShift: list) -> list:
    return [
        [valuesToShift[0][0], valuesToShift[3][1], valuesToShift[2][2], valuesToShift[1][3]],
        [valuesToShift[1][0], valuesToShift[0][1], valuesToShift[3][2], valuesToShift[2][3]],
        [valuesToShift[2][0], valuesToShift[1][1], valuesToShift[0][2], valuesToShift[3][3]],
        [valuesToShift[3][0], valuesToShift[2][1], valuesToShift[1][2], valuesToShift[0][3]]
    ]

# Function 6.2: InvSubBytes()
# Function 6.2.1: inverseSBoxFunction() This inverse will be used by the inverseSubBytes() function
def inverseSBoxFunction(entry: int) -> int:
    return S_BOX_INVERSE[entry]

# Function 6.2.2: InvSubBytes() proper
# This is added to call the sBoxFunction() on each of the words within the rijndaelForwardCipher()
def inverseSubBytes(valuesToSubstitute: list) -> list:
    substitutedValues = []

    for item in range(len(valuesToSubstitute)):
        substitutedValues.append(
            list(map(inverseSBoxFunction, valuesToSubstitute[item]))
        )

    return substitutedValues

# Function 6.3: InvMixColumns()
def inverseMixColumns(valuesToMix: list) -> list:
    mixedColumns = []

    for index in range(len(valuesToMix)):
        mixedColumns.append([
            (xTimesGreaterThanTwo(valuesToMix[index][0], 0x0e) ^ xTimesGreaterThanTwo(valuesToMix[index][1], 0x0b)) ^ xTimesGreaterThanTwo(valuesToMix[index][2], 0x0d) ^ xTimesGreaterThanTwo(valuesToMix[index][3], 0x9),
            xTimesGreaterThanTwo(valuesToMix[index][0], 0x09) ^ xTimesGreaterThanTwo(valuesToMix[index][1], 0x0e) ^ xTimesGreaterThanTwo(valuesToMix[index][2], 0x0b) ^ xTimesGreaterThanTwo(valuesToMix[index][3], 0xd),
            xTimesGreaterThanTwo(valuesToMix[index][0], 0x0d) ^ xTimesGreaterThanTwo(valuesToMix[index][1], 0x09) ^ xTimesGreaterThanTwo(valuesToMix[index][2], 0x0e) ^ xTimesGreaterThanTwo(valuesToMix[index][3], 0xb),
            xTimesGreaterThanTwo(valuesToMix[index][0], 0x0b) ^ xTimesGreaterThanTwo(valuesToMix[index][1], 0x0d) ^ xTimesGreaterThanTwo(valuesToMix[index][2], 0x09) ^ xTimesGreaterThanTwo(valuesToMix[index][3], 0x0e)
        ])

    return mixedColumns

# Step 6.4: The inverse of rijndaelForwardCipher()
# Depends on various functions
def rijndaelInverseCipher(ciphertext: list, numberOfRounds: int, keySchedule: list) -> list[list[list[int]]]:
    decryptedPlaintext = []

    print("\n---DECRYPTION---")

    # We iterate through each block, and apply the entirety of the key to it, at different intervals.
    for block in ciphertext:

        initializedState = addRoundKey(block, keySchedule[numberOfRounds])

        for iteration in range((numberOfRounds - 1), 0, -1):
            inverseShiftRowsState = inverseShiftRows(initializedState)
            inverseSubBytesState = inverseSubBytes(inverseShiftRowsState)
            addRoundKeyState = addRoundKey(
                inverseSubBytesState, keySchedule[iteration])
            initializedState = inverseMixColumns(addRoundKeyState)

        finalInvShiftRowsState = inverseShiftRows(initializedState)
        finalInvSubBytesState = inverseSubBytes(finalInvShiftRowsState)
        finalAddRoundKeyState = addRoundKey(
            finalInvSubBytesState, keySchedule[0])

        decryptedPlaintext.append(finalAddRoundKeyState)

    return decryptedPlaintext


# Step 7: Remove padding - if any - and decode the message.
# To show the resultant ciphertext, this function is also called on the ciphertext message
# All along we are dealing with a list of integers representing our plaintext or ciphertext bytes. We need to unpack the given list to recover our bytes, and subsequently decode the corresponding values to retrieve our original message.
def decodeMessageBytes(plaintextLength: int, messageToDecode: list[list[list[int]]]) -> str:
    decodedText = []
    print("\n---DECODING BYTES---\n")

    # Recover the plaintext bytes from the decrypted (but still encoded) list of values, and convert the integer into a byte value
    for entry in messageToDecode:
        for listEntry in entry:
            for character in listEntry:
                decodedText.append(character.to_bytes())

    # Remove padding, if any, to get back the original string
    if plaintextLength % 16 != 0:
        return b''.join(decodedText).decode("utf-8", "ignore")[:-(16 - (plaintextLength % 16))]
    else:
        return b''.join(decodedText).decode("utf-8", "ignore")


def encryptAndDecryptPlaintext():
    # Step 1a: Receive CLI arguments from user - the message/plaintext, and the key size they'd want
    receivedArguments = parser.parse_args()

    plaintext = receivedArguments.message
    keyLength = receivedArguments.length

    # Step 1b.1: Calculate length of plaintext, a value that will be used when unpadding the original message, or whenever the decodeMessageBytes() function is called
    plaintextLength = len(plaintext)

    print(f"\nPlaintext to encrypt is:\n{Style.BRIGHT}{Fore.BLUE}{plaintext}{Style.RESET_ALL}\nKey length: {Style.BRIGHT}{Fore.YELLOW}{keyLength} bits\n{Style.RESET_ALL}")

    # Step 1b.2: Pad the string. It needs to be at least 16 bytes long. It has been easier, for me, to pad the string *before* partitioning.
    paddedString = padInputString(plaintext)

    partitionedPlaintext = partitionInputString(paddedString)
    roundsToRun, keyToUse = generateKey(keyLength)
    rounds, expandedKey = generateKeySchedule(roundsToRun, keyToUse)
    ciphertext = rijndaelForwardCipher(chunkedList(partitionedPlaintext), rounds, chunkedList(expandedKey))

    # To show users that the message has actually been encrypted, we add this line
    print(f"Our ciphertext is:\n{Style.BRIGHT}{Fore.LIGHTBLUE_EX}{decodeMessageBytes(plaintextLength, ciphertext)}{Style.RESET_ALL}")

    decryptedPlaintext = rijndaelInverseCipher(ciphertext, rounds, chunkedList(expandedKey))
    decodedMessage = decodeMessageBytes(plaintextLength, decryptedPlaintext)
    print(f"Decoded plaintext:{Style.BRIGHT}{Fore.GREEN}\n{decodedMessage}{Style.RESET_ALL}")


if __name__ == "__main__":
    encryptAndDecryptPlaintext()
