# -*- coding: utf-8 -*- 
import os, sys, re, random 
from flask import Flask, jsonify, render_template, request
from cryptography.hazmat.primitives.twofactor.hotp import HOTP
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from pyDes import *

# Create a flask app object using a unique name. In this case we are
# using the name of the current file
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

def is_prime(q):
    if q < 2:
        return False
    elif q == 2:
        return True
    elif not q%2:
        return False
    for i in range(3, int(q**0.5)+1, 2):
        if not q%i:
            return False
        return True
    
# This view method responds to the URL / for the methods GET and POST
@app.route('/', methods=['GET','POST'])
def primitive():
    # Initialize the errors variable to empty string. We will have the error messages
    # in that variable, if any.
    errors = ''
    if request.method == "GET": # If the request is GET, render the form template.
        return render_template("index.html", errors=errors)
    
    if 'aesForm' in request.form:
        # The request is POST with some data, get POST data and validate it.
        # The form data is available in request.form dictionary. Stripping it to remove
        # leading and trailing whitespaces
        aesPlainText = request.form['aesPlainText'].strip()    
        
        # Check if all the fields are non-empty and raise an error otherwise
        if not aesPlainText:
            errors = "Please enter all the fields."
            
        if not errors:
            # If there are no errors, create a dictionary containing all the entered
            # data and pass it to the template to be displayed
            a1 = "Symmetric Encryption\n"
            a2 = "This application will use DES Symmetric Encryption to encrypt and decrypt text\n"
            plainText = "Text to encrypt: "

            getInput = aesPlainText
            backend = default_backend()
            cfb_Key = os.urandom(16)
            aes_Key = os.urandom(32)

            #secretMessage = str.encode(input(plainText))
            secretMessage = str.encode(getInput)

            cipher = Cipher(algorithms.AES(aes_Key), modes.CFB(cfb_Key), backend=backend)
            encryptor = cipher.encryptor()
            encryptedText = encryptor.update(secretMessage) + encryptor.finalize()
            decryptor = cipher.decryptor()
            decryptedText = decryptor.update(encryptedText) + decryptor.finalize()
            
            dataAes = {'aes_Key' : aes_Key,
                    'cfb_Key' : cfb_Key,
                    'encryptedText' : encryptedText,
                    'decryptedText' : decryptedText
                    }
            # Since the form data is valid, render the success template
            return render_template("prim/aes.html", dataAes=dataAes)
        # Render the form template with the error messages
        return render_template("index.html", errors=errors)
    
    if 'desForm' in request.form:
        # The request is POST with some data, get POST data and validate it.
        # The form data is available in request.form dictionary. Stripping it to remove
        desPlainText = request.form['desPlainText'].strip()
        #desBitKey = request.form['desBitKey'].strip()
        #desMode = request.form['desMode'].strip()
        
        # Check if all the fields are non-empty and raise an error otherwise
        if not desPlainText:
            errors = "Please enter all the fields."
        if not errors:
            # If there are no errors, create a dictionary containing all the entered
            # data and pass it to the template to be displayed
            plaintext = desPlainText
            mode = "CBC"
            key = "12345678"

            #key and plain text
            desKey = des(key, mode, "\0\0\0\0\0\0\0\0")
            #print ("Key      : %r" % k.getKey())
            #print ("Plaintext     : %r" % plaintext)
            #desKey = k

            # Encrypted message
            desEnc = desKey.encrypt(plaintext, [], PAD_PKCS5)
            #print ("Encrypted: %r" % d)
            desEncMessage = desEnc       

            # Decrypted message
            desDec = desKey.decrypt(desEncMessage, [],PAD_PKCS5)
            #print ("Decrypted Plaintext: %r" % d)
            desDecMessage = desDec      

            dataDes = {
                    'desPlainText' : desPlainText,
                    'desKey' : desKey,
                    'desEncMessage' : desEncMessage,
                    'desDecMessage' : desDecMessage
                    }
            # Since the form data is valid, render the success template
            return render_template("prim/des.html", dataDes=dataDes)
        # Render the form template with the error messages
        return render_template("index.html", errors=errors)
    
    if 'hmacForm' in request.form:
        # The request is POST with some data, get POST data and validate it.
        # The form data is available in request.form dictionary. Stripping it to remove
        hmacPlainText = request.form['hmacPlainText'].strip()

        # Check if all the fields are non-empty and raise an error otherwise
        if not hmacPlainText:
            errors = "Please enter all the fields."
        if not errors:
            # If there are no errors, create a dictionary containing all the entered
            # data and pass it to the template to be displayed
            shared_key = os.urandom(16)
            # Create a HMAC object
            digest = hmac.HMAC(shared_key, hashes.SHA256(), backend=default_backend())
            # enter the message has input to be hased in bytes
            plaintext = str.encode(hmacPlainText)
            digest.update(plaintext)
            # Finalized and produce the HMAC that will be attached to the message
            hash_code = digest.finalize()

            print ("message", hmacPlainText)
            print ("hash_code", hash_code)
            print ("random Key:", shared_key)

            dataHmac = {
                'hmacPlainText' : hmacPlainText,
                'hash_code' : hash_code,
                'shared_key' : shared_key
                }
        
            # Since the form data is valid, render the success template
            return render_template("prim/hmac.html", dataHmac=dataHmac)
        # Render the form template with the error messages
        return render_template("index.html", errors=errors)    
    
    if 'diffForm' in request.form:
        # The request is POST with some data, get POST data and validate it.
        # The form data is available in request.form dictionary. Stripping it to remove
        diifPlainText = request.form['diifPlainText'].strip()
        diffPub1 = request.form['diffPub1'].strip()
        diffPub2 = request.form['diffPub2'].strip()

        # Check if all the fields are non-empty and raise an error otherwise
        if not diifPlainText or not diffPub1 or not diffPub2:
            errors = "Please enter all the fields."
        if not errors:
            # If there are no errors, create a dictionary containing all the entered
            # data and pass it to the template to be displayed
                        
            Xa = int(diffPub1)
            Xb = int(diffPub2)
            
            diifPlainText = int(diifPlainText)
            check_num = 0
            prK = 2
            a = prK
            #Compute Public Key for first user
            Ya = (a ** Xa) % diifPlainText
            #Compute Public Key for second user
            Yb = (a ** Xb) % diifPlainText
            #Compute shared key
            Ka = (Yb ** Xa) % diifPlainText 
            Kb = (Ya ** Xb) % diifPlainText

            #Shared key should be same value for both users
            print ("primitive_root: prK and prQ")
            print ("1 shared key is", Ka)
            print ("2 shared key is", Kb, "\n")
            print ("1 and 2 secret shared key is",Ka,"\n")  

            print ("primitive_root", prK)
            print ("a_pupKey", Ya)
            print ("a_sharedKey", Ka)
            print ("b_pupKey", Yb)
            print ("b_sharedKey:", Kb)

            dataDiff = {
                'prime' : diifPlainText,
                'primitive_root' : prK,
                'a_pupKey' : Ya,
                'a_sharedKey' : Ka,
                'b_pupKey' : Yb,
                'b_sharedKey' : Kb
                }
                
            # Since the form data is valid, render the success template
            return render_template("prim/diff.html", dataDiff=dataDiff)
        # Render the form template with the error messages
        return render_template("index.html", errors=errors)

    if '2faForm' in request.form:
        # The request is POST with some data, get POST data and validate it.
        # The form data is available in request.form dictionary. Stripping it to remove
        #diifPlainText = request.form['diifPlainText'].strip()

        # Check if all the fields are non-empty and raise an error otherwise
        #if not diifPlainText or not diffPub1 or not diffPub2:
            #errors = "Please enter all the fields."
        if not errors:
            # If there are no errors, create a dictionary containing all the entered
            # data and pass it to the template to be displayed
            
            #Key is a secret key which is being randomly generated bytes
            key2Fa = os.urandom(20)
            #HOTP is an HMAC one-time password algorithm.
            #Length parameter is controls the length of the generated password which must be >=6 and <=8; Is using SHA1() hash function to encrypt
            hotp = HOTP(key2Fa, 6, SHA1(), backend=default_backend())
            #Hotp.generate, generates the random 6 digit token
            hotp_value = hotp.generate(0)
            hotp.verify(hotp_value, 0)
            
            print ("hashed_value: ", hotp_value)
            print ("generated key: ", key2Fa)
            
            data2Fa = {
                'hotp_value' : hotp_value,
                'key2Fa' : key2Fa
                }

            # Since the form data is valid, render the success template
            return render_template("prim/2fa.html", data2Fa=data2Fa)
        # Render the form template with the error messages
        return render_template("index.html", errors=errors)
        
        
# This is the code that gets executed when the current python file is
# executed. 
    
if __name__ == '__main__':
    app.run(debug=True)