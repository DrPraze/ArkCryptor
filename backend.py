
class Methods:
    def SearchCipher(search, lst, cyphers, listitem):
    	text = search.text()
    	lst.clear()
    	for file in cyphers:
            if text in file:
                listitem(file, lst)

    def SearchWikipedia(wiki):
    	# cipher = selected cipher, define that
    	result = wiki.summary(cipher, sentences=100)
    	#put result in the about selected cipher display

    def open_text(self, openfile, settext, out):
        filename = openfile(self, 'Open text file', "*.txt")
        settext(filename[0])

        if filename[0]:
            f = open(filename[0], 'r')
            with f:
                data = f.read()
                out(data)

    def SelectCipher(item, settext):
        selected = item.text()
        settext(selected)
        #show info of the selected text here

    def OpenImage(self, openfile, settext, QL, QP, G):
        img = openfile(self, 'Open Image', '*.png')
        settext(img[0])
        
        label = QL()
        G.addWidget(label)
        pix = QP(img[0])
        label.setPixmap(pix)
        # G.setCentralWidget(label)


    def OpenFolder(self, openfile, settext):
        folder = openfile(None, 'select a folder', 'C://')
        settext(folder)

    def encodeSteganography(viewable, img, text, output):
        from stegan import encode, encrypt_to_image, genData, modPix, encode_enc
        import hashlib, os, codecs
        from base64 import b64encode, b64decode
        from Cryptodome.Cipher import AES
        from Cryptodome.Random import get_random_bytes
        from PIL import Image, ImageDraw
 
        if viewable == True:
            encode(img, text, output)
        else:
            encrypt_to_image(text, img)

    def decodeSteganography(viewable, img, text, output):
        from stegan import encode, encrypt_to_image, genData, modPix, encode_enc
        import hashlib, os, codecs
        from base64 import b64encode, b64decode
        from Cryptodome.Cipher import AES
        from Cryptodome.Random import get_random_bytes
        from PIL import Image, ImageDraw
 
        if viewable == True:
            decode(img)
        else:
            decrypt_to_text(img)        

    def genHash(file, settext):
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(file, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096),b""):
                sha256_hash.update(byte_block)
        fin_hash = sha256_hash.hexdigest()

        settext(fin_hash)
        



        
