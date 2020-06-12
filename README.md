# Codex
 A python tool for automated cipher decryption by **@Syn7h3x**

## How to use
`python3 codex.py [options] {-a | -c cipher} ciphertext`
##### Examples
* `python3 codex.py -c hexadecimal 48656C6C6F` or `python3 codex.py -c hex 48656C6C6F`

* `python3 codex.py -a "9‡‡*(5("`

* `python3 codex.py -c vigenere TJVGKJP -k synth `

* `python3 codex.py -c caesar Qfcpjmai -r 24`

* `python3 codex.py -a -q IJWDIY3LMIYHS=== -o output_file`


#### Options
flags | description
------------ | -------------
-a, --all | Try to decode in all ciphers available
-A, --ascii | Use ASCII table instead of alphabet on Caesar Cipher
-b, --bruteforce | Caesar bruteforce mode (Starts from 1 and increment the rotation until the specified rotation)
-c, --cipher | Specifies the cipher method to decode
-k, --key | Specifies the key for Vigenère decoder
-l, --less | Return only the decoded text
-n, --num, | Return the numeric value instead of ASCII
-o, --output | Write the result in a file
-p, --punctuation | Do not ignore punctuations
-q, --quiet | Do not print the result on screen
-r, --rotation | Specifies Caesar Cipher rotation
-s, --separator | Specifies a custom separator
-v, --verbose | Return even the failed tries

#### Ciphers 
* Binary
* Octal
* Decimal
* Hexadecimal
* Base 32
* Base 64
* Morse 
* AtBash
* A1Z26
* ROT 13
* T9
* Gold Bug
* Caesar cipher
* Vigenère

