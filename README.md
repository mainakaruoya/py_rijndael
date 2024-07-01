### Advanced Encryption Standard (AES)
This is a CLI-based implementation of the core AES algorithm, **Rijndael,** in Python. It takes a plaintext message, as well as the key size (128, 192, or 256 bits) to use, and then encrypts and decrypts the message, printing out the ciphertext, and the subsequent decrypted ciphertext (i.e., the original plaintext).

This implementation has endeavored to follow what is defined in the US NIST Federal Information Processing Standards (FIPS) 197 plublication, found [here](https://doi.org/10.6028/NIST.FIPS.197-upd1) (link is to a PDF document; alternatively, the publication's web page is [here](https://csrc.nist.gov/pubs/fips/197/final)).

**Note:** it only accepts characters that can be represented as values between 0-255.

### ⚠️ Disclaimer
Though this implementation over here aimed to follow the standard as closely as possible, it is not recommended to use this in a production environment. It is better to use libraries like `Cryptogrpahy`, `PyNaCl` and `Pycryptodome` which have been more thoroughly vetted and importantly, generally optimized for such use.

### Prerequisites
The plaintext, key length, and decoded plaintext are color-coded using `colorama`, hence the need to install it using pip:
`pip install colorama`

### Usage and Options
All flags/options are mandatory.
Use `python3` instead of `python` if working from Linux.

Usage: `rijndael.py -m <plaintext> -l <key length>`

~~~
Options:
  -h, --help            show this help message and exit
  -m <plaintext>, --message <plaintext>
                        The message to encrypt and decrypt.
  -l <key length>, --length <key length>
                        Key length for the AES function. The possible values that can be selected are 128, 192 or 256 bits
~~~