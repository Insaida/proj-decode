#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import optparse
import binascii
import base64
import string
import Crypto
from Crypto.Hash import *
from Crypto.Cipher import *
from Crypto.PublicKey import RSA
from Crypto import *
from pycipher import Foursquare





# Tables for CRYPO encoder Base64 translations
tableB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
tableATOM128 = "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC"
tableMEGAN35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5"
tableZONG22 = "ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2"
tableHAZZ15 = "HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5"
tableGILA7 = "7ZSTJK+W=cVtBCasyf0gzA8uvwDEq3XH/1RMNOILPQU4klm65YbdeFrx2hij9nopG"
tableESAB46 = "ABCDqrs456tuvNOPwxyz012KLM3789=+QRSTUVWXYZabcdefghijklmnopEFGHIJ/"
tableTRIPO5 = "ghijopE+G78lmnIJQRXY=abcS/UVWdefABCs456tDqruvNOPwx2KLyz01M3Hk9ZFT"
tableTIGO3FX = "FrsxyzA8VtuvwDEqWZ/1+4klm67=cBCa5Ybdef0g2hij9nopMNO3GHIRSTJKLPQUX"
tableFERON74 = "75XYTabcS/UVWdefADqr6RuvN8PBCsQtwx2KLyz+OM3Hk9ghi01ZFlmnjopE=GIJ4"

# Text output colors
class txtcolors:
    PURPLE = '\033[95m'
    HEADER = '\033[94m' # Blue
    KEYWORD = '\033[92m' # Green
    WARNING = '\033[93m'
    FAIL = '\033[91m' # Red
    ENDC = '\033[0m' # Ends color scheme
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Change color of output if a key word is matched
def checkKeyWords(result):
    if "admin" in result or "root" in result or \
       "administrator" in result or "key" in result or \
       "pass" in result or "flag" in result:
        return "key"
    elif "Invalid" in result or "Non-printable" in result:
        return "fail"
    else:
        return "norm"

# Signal whether or not the result contains non-printable characters
def checkNonPrintable(result):
    if all(c in string.printable for c in result):
        return False
    else:
        return True

# Output printing function
def printOutput(alg, result):
    # Print upper border with a standard length unless "none" is given
    if alg != "none":
        print txtcolors.BOLD + txtcolors.HEADER + "----- %s" %alg, "-" * \
              (63 - len(alg)) + txtcolors.ENDC
    # Print result
    if result != "":
        if checkKeyWords(result) == "key":
            print txtcolors.KEYWORD + result + txtcolors.ENDC
        elif checkKeyWords(result) == "fail":
            print txtcolors.FAIL + result + txtcolors.ENDC
        else:
            print result
    
# Prevent the code below from running if it's just being imported
if __name__ == "__main__":

    # Define options and args
    parser = optparse.OptionParser()
    parser.add_option("-o", "--output", action="store", type="string", 
                      dest="outputFileName",
                      help="Write output to a file")

    (options, args) = parser.parse_args()

    # Handle options and args
    if options.outputFileName:
        print "Caught the output arg! File is ", options.outputFileName

    # Make sure we get something to decode
    if len(args) < 1:
        print "Please specify the string to decrypt. Use -h for help."
        sys.exit(1)

    # Read in ciphertext
    ciphertext = args[0]
    printOutput("CIPHERTEXT", ciphertext)

    # Decode Bin to ASCII
    try:
        ciphertext_bin = ciphertext.replace(" ","")
        ciphertext_hx = int('0b'+ciphertext_bin, 2)
        result_btoa = binascii.unhexlify('%x' %ciphertext_hx)
        if checkNonPrintable(result_btoa):
            printOutput("Bin to ASCII", "Non-printable chars in result")
        else:
            printOutput("Bin to ASCII", result_btoa)
    except TypeError:
        printOutput("Bin to ASCII", "Invalid string for this operation.")    
    except ValueError:
        printOutput("Bin to ASCII", "Invalid string for this operation.")    

    # Decode Hex to ASCII
    # Valid formats: 7071, "70 71", \x70\x71, "0x70 0x71"
    ciphertext_hex = ciphertext.replace("0x","")
    ciphertext_hex = ciphertext_hex.replace("x","")
    ciphertext_hex = ciphertext_hex.replace(" ","")
    try:
        result_htoa = binascii.unhexlify(ciphertext_hex)
        if checkNonPrintable(result_htoa):
            printOutput("Hex to ASCII", "Non-printable chars in result")
        else:
            printOutput("Hex to ASCII", result_htoa)
    except TypeError:
        printOutput("Hex to ASCII", "Invalid string for this operation.")  

    # Decode Base64
    try:
        result_b64 = base64.b64decode(ciphertext)
        if checkNonPrintable(result_b64):
            printOutput("Base64", "Non-printable chars in result")
        else:
            printOutput("Base64", result_b64)
    except TypeError:
        printOutput("Base64", "Invalid string for this operation.")

    # Decode reverse-order
    result_reverse = ""
    for letternum in range(len(ciphertext) -1, -1, -1):
        result_reverse += ciphertext[letternum]
    printOutput("Reverse String", result_reverse)

    # Decode Caesar Shift, aka rotation ciphers
    # First check to see if there are even any letters here
    flg_alpha = False
    for letternum in range(0, len(ciphertext)):
        if ciphertext[letternum].isalpha():
            flg_alpha = True
            break
    if flg_alpha == True:
        # 25 possible shifts to go through the whole alphabet
        for shiftnum in range(1,26):
            result_caesarshift = ""
            for letternum in range(0, len(ciphertext)):
                if ciphertext[letternum].isalpha():
                    letterord = ord(ciphertext[letternum])
                    resultord = letterord - shiftnum
                    # Rotate back to the start, if reaching end points
                    if ciphertext[letternum].isupper():
                        if resultord < ord("A"):
                            resultord += 26
                    if ciphertext[letternum].islower():
                        if resultord < ord("a"):
                            resultord += 26
                    result_caesarshift += chr(resultord)
                # Don't shift symbols/spaces
                else:
                    result_caesarshift += ciphertext[letternum]
            if shiftnum == 1:
                outputTitle = "Caesar Shift/ROT(n)" 
                printOutput(outputTitle, "")
            if checkKeyWords(result_caesarshift) == "key":
                print txtcolors.KEYWORD + "%02d: "%shiftnum + result_caesarshift + \
                      txtcolors.ENDC
            else:
                print "%02d: "%shiftnum + result_caesarshift
    else:
        printOutput("Caesar Shift", "No letters to rotate")

    # Decode ATOM-128, MEGAN-35, ZONG-22, HAZZ-15 ciphers
    # These all follow the same principle for decoding:
    # Translate the string to b64 using the tables above, then decode the b64
    dictTables = {"ATOM-128":tableATOM128, "MEGAN-35":tableMEGAN35, \
                  "ZONG-22":tableZONG22, "HAZZ-15":tableHAZZ15, \
                  "GILA-7":tableGILA7, "ESAB-46":tableESAB46, \
                  "TRIPO-5":tableTRIPO5, "TIGO-3FX":tableTIGO3FX, \
                  "FERON-74":tableFERON74 }
    printOutput("CRYPO CIPHERS", "")
    for method in ["ATOM-128", "MEGAN-35", "ZONG-22", "HAZZ-15", \
                   "GILA-7", "ESAB-46", "TRIPO-5", "TIGO-3FX", "FERON-74"]:
        try:
            trans = string.maketrans(dictTables[method], tableB64)
            result_method = base64.b64decode(ciphertext.translate(trans))
            if checkNonPrintable(result_method):
                printOutput("none", method + ": " + "Non-printable chars in result")
            else:
                printOutput("none", method + ": " + result_method)
        except TypeError:
            print txtcolors.FAIL + method + ": Invalid string for this operation" + \
                  txtcolors.ENDC

    # Decode 
    try:
        result_b64 = base64.b64decode(ciphertext)
        if checkNonPrintable(result_b64):
            printOutput("Base64", "Non-printable chars in result")
        else:
            printOutput("Base64", result_b64)
    except TypeError:
        printOutput("Base64", "Invalid string for this operation.")


    #New Ciphers
    try:
        #Decode SHA256
        SHA256.new(ciphertext).hexdigest() == result_sha256
        if checkNonPrintable(result_sha256):
            printOutput("SHA256", "Non-printable chars in result")
        else:
            printOutput("SHA256", result_sha256)
    except TypeError:
        printOutput("SHA256", "Invalid string for this operation.")

#Not written this yet.
        #Decode MD5 
        def get_file_checksum(filename):
            h = MD5.new()
            return h.hexdigest()


#Not written this yet.

    


#Not written this yet.

    try:
        des = DES.new('01234567', DES.MODE_ECB)
        result_des = des.decrypt(ciphertext)
        if checkNonPrintable(result_des):
            printOutput("DES", "Non-printable chars in result")
        else:
            printOutput("DES", result_des)
    except TypeError:
        printOutput("DES", "Invalid string for this operation.")


#Not written this yet.

            #DES CFB

            
            iv = Random.get_random_bytes(8)
            des1 = DES.new('01234567', DES.MODE_CFB, iv)
            des2 = DES.new('01234567', DES.MODE_CFB, iv)
            text = 'abcdefghijklmnop'
            cipher_text = des1.encrypt(text)
            cipher_text
            des2.decrypt(cipher_text)


#Not written this yet.


            #Stream Ciphers
            #ARC4
    try:
        obj1 = ARC4.new('01234567')
        obj2 = ARC4.new('01234567')
    
        result_arc4 = obj2.decrypt(ciphertext)
        if checkNonPrintable(result_arc4):
            printOutput("ARC4", "Non-printable chars in result")
        else:
            printOutput("ARC4", result_arc4)
    except TypeError:
        printOutput("ARC4", "Invalid string for this operation.")

#Not written this yet.

            #DES3

    try:
        def encrypt_file(in_filename, out_filename, chunk_size, key, iv):
            des3 = DES3.new(key, DES3.MODE_CFB, iv)
            with open(in_filename, 'r') as in_file:
                with open(out_filename, 'w') as out_file:
                    while True:
                        chunk = in_file.read(chunk_size)
                        if len(chunk) == 0:
                            break
                        elif len(chunk) % 16 != 0:
                            chunk += ' ' * (16 - len(chunk) % 16)
                        out_file.write(des3.encrypt(chunk))
     
        def decrypt_file(in_filename, out_filename, chunk_size, key, iv):
            des3 = DES3.new(key, DES3.MODE_CFB, iv)
     
                with open(in_filename, 'r') as in_file:
                    with open(out_filename, 'w') as out_file:
                        while True:
                            chunk = in_file.read(chunk_size)
                            if len(chunk) == 0:
                                break
                                out_file.write(des3.decrypt(chunk))


#Not written this yet.

      #      iv = Random.get_random_bytes(8)
      #      with open('to_enc.txt', 'r') as f:
     #           print 'to_enc.txt: %s' % f.read()
     #           encrypt_file('to_enc.txt', 'to_enc.enc', 8192, key, iv)
    #        with open('to_enc.enc', 'r') as f:
    #            print 'to_enc.enc: %s' % f.read()
   #         decrypt_file('to_enc.enc', 'to_enc.dec', 8192, key, iv)
     #       with open('to_enc.dec', 'r') as f:
   #             print 'to_enc.dec: %s' % f.read()


#Not written this yet.

    try:
        random_generator = Random.new().read
        key = RSA.generate(1024, random_generator)
        key
        public_key = key.publickey()
        enc_data = public_key.encrypt('abcdefgh', 32)
        enc_data
        key.decrypt(enc_data)




four1='ZGPTFOIHMUWDRCNYKEQAXVSBL'

four2='MFNBDCRHSAXYOGVITUEWLQZKP'

phrase='ATTACK AT DAWN'


if (len(sys.argv)>1):
        four1=str(sys.argv[1])
if (len(sys.argv)>2):
        four2=str(sys.argv[2])
if (len(sys.argv)>3):
        phrase=str(sys.argv[3])

from pycipher import Foursquare
s = Foursquare(four1,four2)

res=Foursquare(key1=four1,key2=four2).encipher(phrase)
print ("Cipher: ",res)
print ("Decipher: ",Foursquare(key1=four1,key2=four2).decipher(res))