
class Methods:
    def SearchCipher(search, lst, cyphers, listitem):
    	# text = self.lst.findItems(self.search.text(), 
    	# 	Qt.MatchContains|Qt.MatchCaseSensitive)
    	text = search.text()
    	lst.clear()
    	for file in cyphers:
            if text in file:
                listitem(file, lst)

    def SearchWikipedia():
    	# cipher = selected cipher, define that
    	result = wikipedia.summary(cipher, sentences=100)
    	#put result in the about selected cipher display

    def open_text(self, openfile, settext, out):
    	filename = openfile(self, 'Open text file')
    	settext(filename[0])

    	if filename[0]:
    		f = open(filename[0], 'r')
    		with f:
    			data = f.read()
    			out(data)

    def SelectCipher():
        print('Cipher Selected')

    def OpenImage(self, openfile, settext):
        img = openfile(self, 'Open Image')
        settext(filename[0])
        #Open image in steganography area
