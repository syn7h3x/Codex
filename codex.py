#!/bin/python3
# -*- coding: UTF-8 -*-
# by @Syn7h3x

import argparse
import base64 as b64

BLUE = '\033[94m'
GREEN = '\033[32m'
WHITE = '\033[97m'
RED = '\033[31m'
ENDC = '\033[0m'
BOLD = '\033[1m'

help_message = '''usage: Codex.py [OPTIONS] {-a | -c CIPHER} cipher_text

required arguments:
  cipher_text           The ciphered text to be decoded
  -a, --all             Try to decode in almost all available ciphers (Caesar
                        and Viginere are exceptions)
  -c, --cipher CIPHER   The cipher method to decode

optional arguments:
  -A, --ascii          		Use ascii table instead of alphabet on Caesar Cipher

  -b, --bruteforce      	Caesar bruteforce mode

  -h, --help            	show this help message and exit

  -k, --key KEY     		Specifies a key for vigenere

  -l, --less            	Show only the decoded text

  -n, --num             	Show the numeric value instead of ASCII

  -o, --output OUTPUT   	Write the result in a file

  -p, --punctuation     	Do not ignore ponctuations and other symbols

  -q, --quiet           	Do not display the result on screen

  -r, --rotation ROTATION       Specifies Caesar Cipher rotation

  -s, --separator SEPARATOR 	Specifies the separator

  -v, --verbose			Return even the failed tries

  -w, --wordlist WORDLIST	Read a wordlist as key for vigenere


specific ciphers options:
  Binary [-n]

  Octal [-n]

  Decimal [-n]

  Hexadecimal [-n]

  Base32

  Base64

  T9

  AtBash 

  A1Z26 [-s]

  Morse

  GoldBug

  ROT13

  Caesar {-r} [-b, -A]

  Vigenere {-k | -w}

  '''

decoders = ['Base32', 'Base64', 'T9', 'A1Z26', 'Morse', 'GoldBug']
dicts = ['AtBash', 'ROT13']
base_list = {'Binary': 2, 'Octal': 8, 'Decimal': 10, 'Hexadecimal': 16}
sizes = {2: 8, 8: 3, 10: 3, 16: 2}


class MyParser(argparse.ArgumentParser):
    def format_help(self):
        return help_message


parser = MyParser(usage='codex.py [OPTIONS] {-a | -c CIPHER} cipher_text')
group = parser.add_mutually_exclusive_group()
group2 = parser.add_mutually_exclusive_group(required=True)
parser.add_argument("cipher_text", help="The ciphered text to be decoded", type=str)
parser.add_argument("-v", "--verbose", action='store_true')
parser.add_argument("-s", "--separator", help='Specifies the separator', default=' ', type=str)
parser.add_argument("-n", "--num", help="Show the numeric value instead of ASCII", action='store_true')
parser.add_argument("-o", "--output", help="Write the result in a file")
group.add_argument("-l", "--less", help="Show only the decoded text", action='store_true')
group.add_argument("-q", "--quiet", help="Do not display the result on screen", action='store_true')
group2.add_argument("-a", "--all", help="Try to decode in almost all available ciphers (Caesar and Viginere are "
                                        "exceptions)", action='store_true')
group2.add_argument("-c", "--cipher", help="The cipher method to decode", type=str)
parser.add_argument("-b", "--bruteforce", help='Caesar bruteforce method', action='store_true')
parser.add_argument("-r", "--rotation", help='Specifies Caesar Cipher rotation', type=int, default=25)
parser.add_argument('-A', '--ascii', help='Use ascii table instead of alphabet on Caesar Cipher', action='store_true')
parser.add_argument('-p', '--punctuation', help="Do not ignore ponctuations and other symbols", action='store_false',
                    default=True)
parser.add_argument('-w', '--wordlist', help='Read a wordlist as key for vigenere')
parser.add_argument('-k', '--key', help='Specifies a key for vigenere', default='', type=str)
args = parser.parse_args()

alphabet = [chr(i + 97) for i in range(26)]

AtBash = {'A': 'Z', 'B': 'Y', 'C': 'X', 'D': 'W', 'E': 'V', 'F': 'U', 'G': 'T', 'H': 'S', 'I': 'R', 'J': 'Q',
          'K': 'P', 'L': 'O', 'M': 'N', 'N': 'M', 'O': 'L', 'P': 'K', 'Q': 'J', 'R': 'I', 'S': 'H', 'T': 'G',
          'U': 'F', 'V': 'E', 'W': 'D', 'X': 'C', 'Y': 'B', 'Z': 'A'}

Morse = {'.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I',
         '.---': 'J', '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
         '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y', '--..': 'Z', '.----': '1',
         '..---': '2', '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9',
         '-----': '0', '--..--': ', ', '.-.-.-': '.', '..--..': '?', '-..-.': '/', '-....-': '-', '-.--.': '(',
         '-.--.-': ')', '/': ' '}

GoldBug = {'5': 'A', '2': 'B', '-': 'C', '†': 'D', '8': 'E', '1': 'F', '3': 'G', '4': 'H',
           '6': 'I', ',': 'J', '7': 'K', '0': 'L', '9': 'M', '*': 'N', '‡': 'O', '.': 'P',
           '$': 'Q', '(': 'R', ')': 'S', ';': 'T', '?': 'U', '¶': 'V', ']': 'W', '¢': 'X', ':': 'Y', '[': 'Z'}

A1Z26 = {'1': 'A', '2': 'B', '3': 'C', '4': 'D', '5': 'E', '6': 'F', '7': 'G', '8': 'H', '9': 'I', '10': 'J', '11': 'K',
         '12': 'L', '13': 'M', '14': 'N', '15': 'O', '16': 'P', '17': 'Q', '18': 'R', '19': 'S', '20': 'T', '21': 'U',
         '22': 'V', '23': 'W', '24': 'X', '25': 'Y', '26': 'Z'}

ROT13 = {'N': 'A', 'O': 'B', 'P': 'C', 'Q': 'D', 'R': 'E', 'S': 'F', 'T': 'G', 'U': 'H', 'V': 'I', 'W': 'J', 'X': 'K',
         'Y': 'L', 'Z': 'M', 'A': 'N', 'B': 'O', 'C': 'P', 'D': 'Q', 'E': 'R', 'F': 'S', 'G': 'T', 'H': 'U', 'I': 'V',
         'J': 'W', 'K': 'X', 'L': 'Y', 'M': 'Z'}

T9_table = {'0': ' ', '21': 'A', '22': 'B', '23': 'C', '31': 'D', '32': 'E', '33': 'F', '41': 'G', '42': 'H', '43': 'I',
            '51': 'J', '52': 'K', '53': 'L', '61': 'M', '62': 'N', '63': 'O', '71': 'P', '72': 'Q', '73': 'R',
            '74': 'S', '81': 'T', '82': 'U', '83': 'V', '91': 'W', '92': 'X', '93': 'Y', '94': 'Z'}

Multitap_table = {'222': 'C', '22': 'B', '2': 'A', '333': 'F', '33': 'E', '3': 'D', '444': 'I', '44': 'H', '4': 'G',
                  '555': 'L', '55': 'K', '5': 'J', '666': 'O', '66': 'N', '6': 'M', '7777': 'S', '777': 'R', '77': 'Q',
                  '7': 'P', '888': 'V', '88': 'U', '8': 'T', '9999': 'Z', '999': 'W', '99': 'X', '9': 'Y', '0': ' '}

punctuation = [' ', '!', "#", '&', '$', '@', '%', '(', ')', '[', ']', '{', '}', '=', '-', ':', ';', '>', '<', '?', '.',
               ',', '_', '"', "'", '\\', '/']
cipher = ''
file_out = ''
vigenere_keys = args.key

if not args.punctuation:
    punctuation = ' '

if args.wordlist:
    with open(args.wordlist, 'r') as wordlist:
        for line in wordlist.readlines():
            vigenere_keys += line[:len(args.cipher_text)] + '\n'
        vigenere_keys = vigenere_keys.strip()

if args.cipher is not None:
    cipher = args.cipher.lower()
    if cipher in 'base32':
        cipher = 'Base32'
    elif cipher in 'base64':
        cipher = 'Base64'
    elif cipher in 'binary':
        cipher = 'Binary'
    elif cipher in 'octal':
        cipher = 'Octal'
    elif cipher in 'decimal':
        cipher = 'Decimal'
    elif cipher in 'hexadecimal':
        cipher = 'Hexadecimal'
    elif cipher in 'atbash':
        cipher = 'AtBash'
    elif cipher in 'goldbug':
        cipher = 'GoldBug'
    elif cipher in 'a1z26':
        cipher = 'A1Z26'
    elif cipher in 'morse':
        cipher = 'Morse'
    elif cipher in 'dtmf':
        cipher = 'DTMF'
    elif cipher in 't9':
        cipher = 'T9'
    elif cipher in 'caesarcesarshiftrot':
        cipher = 'Caesar'
    elif cipher in 'vigenere':
        cipher = 'Vigenere'
    elif cipher in 'rot13':
        cipher = 'ROT13'


def style(text, is_found, cipher_method, less=False, verbose=False):
    if less and is_found:
        return f"{WHITE}{text}{ENDC}"
    elif verbose:
        if is_found:
            return f"{GREEN}[{WHITE}+{GREEN}]{WHITE} {cipher_method}: {text} {ENDC}"
        else:
            return f"{RED}[{WHITE}-{RED}]{WHITE} {cipher_method}: {text} {ENDC}"
    elif is_found:
        return f"{GREEN}[{WHITE}+{GREEN}]{WHITE} {cipher_method}: {text} {ENDC}"


def cut(string, size):
    string_cutted = ''
    cutted = []
    for i in range(len(string)):
        if i % size == 0:
            cutted.append(string_cutted)
            string_cutted = ''
        string_cutted += string[i]
        if i == len(string) - 1:
            cutted.append(string_cutted)
    return cutted[1:]


def to_num(char):
    return alphabet.index(char.lower())


def to_char(num):
    return alphabet[num % 26]


def sub_cipher(text, cipher_dict):
    sub_decoded = ''
    string = ''
    for letter in text:
        if letter not in punctuation:
            sub_decoded += cipher_dict[(letter.upper())] if letter.isupper() else cipher_dict[letter.upper()].lower()
            string += letter
        else:
            sub_decoded += letter
    if string:
        return sub_decoded
    else:
        raise ValueError


def base_decode(text, base_n):
    n = base_list[base_n]
    base_decoded = ""
    if ' ' in text:
        string = text.split(' ')
    else:
        string = cut(text, sizes[n])
    for i in string:
        if args.num:
            base_decoded += str(int(i, n))
        else:
            base_decoded += chr(int(i, n))
    return base_decoded


def base32(text):
    return b64.b32decode(text).decode('UTF-8')


def base64(text):
    return b64.b64decode(text).decode('UTF-8')


def t9(text):
    t9_decoded = ''
    if ' ' in text:
        for i in text.split():
            t9_decoded += t9(i)
            t9_decoded += ' '
    else:
        cutted_txt = cut(text, 2)
        for i in cutted_txt:
            t9_decoded += T9_table[i]
    return t9_decoded


def a1z26(text, sep=args.separator):
    decoded_a1z26 = ''
    for word in text.split():
        for char in word.split(sep):
            decoded_a1z26 += A1Z26[char]
        decoded_a1z26 += ' '
    return decoded_a1z26


def morse(text):
    decoded_morse = ''
    for word in text.split('/'):
        for char in word.split():
            decoded_morse += Morse[char]
        decoded_morse += ' '
    return decoded_morse


def goldbug(text):
    goldbug_decoded = ''
    for letter in text:
        if letter != " ":
            goldbug_decoded += GoldBug[letter]
        return goldbug_decoded


def caesar(text, rot, bruteforce=False, ascii_mode=False):
    decoded_caesar = ''
    bottom = False
    if bruteforce:
        decoded_caesar += '\n'
        step = -1 if rot < 0 else 1
        for rotation in range(step, rot + step, step):
            if bottom:
                decoded_caesar = decoded_caesar[:-1 * (4 + len(str(rotation)))]
                decoded_caesar += f'\n{RED}[{BOLD}Ascii Bottom{RED}]{ENDC}'
                break
            if not args.less:
                decoded_caesar += f'\n {BLUE}[{ENDC}{BOLD}ROT {rotation}{BLUE}]{ENDC} '
            if ascii_mode:
                for i in range(len(text)):
                    if int(ord(text[i]) - rotation) < 0:
                        bottom = True
                        break
                    decoded_caesar += chr(int(ord(text[i])) - rotation)
            else:
                for n in range(len(text)):
                    if text[n].lower() in alphabet:
                        decoded_caesar += to_char(to_num(text[n]) - rotation).upper() if text[n].isupper() else \
                            to_char(to_num(text[n]) - rotation)
                    else:
                        decoded_caesar += text[n]
            decoded_caesar += '\n'
        return decoded_caesar
    else:
        if ascii_mode:
            for i in range(len(text)):
                if int(ord(text[i]) - rot) < 0:
                    decoded_caesar += 'Impossible to print all characteres'
                    break
                decoded_caesar += chr(int(ord(text[i])) - rot)
        else:
            for i in range(len(text)):
                if text[i].lower() in alphabet:
                    decoded_caesar += to_char(to_num(text[i]) - rot).upper() if text[i].isupper() \
                        else to_char(to_num(text[i]) - rot)
                else:
                    decoded_caesar += text[i]
        return decoded_caesar


def vigenere(text, keys):
    final_out = '\n'
    keys = keys.split('\n')
    for key in keys:
        decoded_viginere = ''
        count = 0
        n_key = [to_num(i) for i in key]
        limit = len(key)
        for i in range(len(text)):
            if text[i].lower() in alphabet:
                new_char = to_char(to_num(text[i]) - n_key[count % limit])
                decoded_viginere += new_char.upper() if text[i].isupper() else new_char.lower()
                count += 1
            else:
                decoded_viginere += text[i]
        if args.wordlist:
            final_out += f'{BLUE}\n[{ENDC}{key}{BLUE}]{ENDC} {decoded_viginere}\n'
        else:
            return decoded_viginere
    return final_out


def remove_color(text):
    return text.replace(GREEN, '').replace(WHITE, '').replace(RED, '').replace(BLUE, '').replace(BOLD, '')


if args.all:
    for base in base_list:
        decoded = ''
        found = True

        try:
            decoded = base_decode(args.cipher_text, base)
            if not decoded.strip():
                raise ValueError
        except (ValueError, IndexError, KeyError):
            found = False

        out = style(decoded, found, base, less=args.less, verbose=args.verbose)
        if out is not None:
            if not args.quiet:
                print(out)
            if args.output:
                file_out += style(decoded, found, base, less=args.less, verbose=args.verbose)
    for decoder in decoders:
        decoded = ''
        found = True

        try:
            decoded = eval(f"{decoder.lower()}('{args.cipher_text}')")
            if not decoded.strip():
                raise ValueError
        except (ValueError, IndexError, KeyError):
            found = False

        out = style(decoded, found, decoder, less=args.less, verbose=args.verbose)
        if out is not None:
            if not args.quiet:
                print(out)
            if args.output:
                file_out += style(decoded, found, decoder, less=args.less, verbose=args.verbose)
    for dic in dicts:
        decoded = ''
        found = True
        try:
            decoded = sub_cipher(args.cipher_text, eval(dic))
            if not decoded.strip():
                raise ValueError
        except (ValueError, IndexError, KeyError):

            found = False
        out = style(decoded, found, dic, less=args.less, verbose=args.verbose)
        if out is not None:
            if not args.quiet:
                print(out)
            if args.output:
                file_out += out

else:
    decoded = ''
    found = True

    try:
        if cipher in decoders:
            decoded = eval(f"{cipher.lower()}('{args.cipher_text}')")
        elif cipher in base_list:
            decoded = base_decode(args.cipher_text, cipher)
        elif cipher in dicts:
            decoded = sub_cipher(args.cipher_text, eval(cipher))
        elif cipher == "Caesar":
            decoded = caesar(args.cipher_text, rot=args.rotation, bruteforce=args.bruteforce, ascii_mode=args.ascii)
        elif cipher == "Vigenere":
            if not vigenere_keys:
                decoded = 'A key must be specified'
                raise ValueError
            decoded = vigenere(args.cipher_text, vigenere_keys)
        else:
            decoded = 'Unknown Cipher'
            raise ValueError
        if not decoded.strip():
            raise ValueError

    except (ValueError, IndexError, KeyError):
        found = False

    out = style(decoded, found, cipher, less=args.less, verbose=True)
    if out is not None:
        print(out)
        if args.output:
            file_out += out

if args.output:
    file = open(f"{args.output}", "w")
    file.write(remove_color(file_out))
