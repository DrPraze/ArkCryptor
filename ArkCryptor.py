import sys, time, wikipedia
from PyQt5 import QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from backend import Methods as M

class Window(QtWidgets.QWidget):
    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        self.setWindowTitle("ArkCryptor")
        self.setGeometry(100, 100, 600, 530)
        self.setFixedSize(600, 530)
        app.setStyle("Fusion")
        dark_palette = QPalette()

        dark_palette.setColor(QPalette.Window, QColor(46, 47, 48))
        dark_palette.setColor(QPalette.WindowText, QColor(255, 201, 14))
        dark_palette.setColor(QPalette.Light, QColor(255, 242, 0))
        dark_palette.setColor(QPalette.Midlight, QColor(227, 227, 227))
        dark_palette.setColor(QPalette.Dark, QColor(64, 66, 68))
        dark_palette.setColor(QPalette.Mid, QColor(160, 160, 160))
        dark_palette.setColor(QPalette.Text, QColor(255, 201, 14))
        dark_palette.setColor(QPalette.BrightText, QColor(255, 242, 0))
        dark_palette.setColor(QPalette.Button, QColor(64, 66, 68))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 201, 14))  
        dark_palette.setColor(QPalette.Base, QColor(46, 47, 48))
        dark_palette.setColor(QPalette.Shadow, QColor(105, 105, 105))
        dark_palette.setColor(QPalette.Highlight, QColor(0, 0, 0, 102))
        dark_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Link, QColor(0, 122, 244))
        dark_palette.setColor(QPalette.LinkVisited, QColor(165, 122, 255))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 54, 55))
        dark_palette.setColor(QPalette.NoRole, QColor(0, 0, 0))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(50, 50, 50, 102))
        dark_palette.setColor(QPalette.ToolTipText, QColor(255, 201, 14))
        dark_palette.setColor(QPalette.Disabled, QPalette.Window, QColor(68, 68, 68, 255))
        dark_palette.setColor(QPalette.Disabled, QPalette.WindowText, QColor(164, 166, 168, 96))
        dark_palette.setColor(QPalette.Disabled, QPalette.Text, QColor(164, 166, 168, 96))
        dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(164, 166, 168, 96))
        dark_palette.setColor(QPalette.Disabled, QPalette.Base, QColor(68, 68, 68, 255))
        dark_palette.setColor(QPalette.Disabled, QPalette.Shadow, QColor(0, 0, 0, 255))

        app.setPalette(dark_palette)
        app.setStyleSheet("QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }")
        self.win1()

    def win1(self):
    	self.layout = QtWidgets.QVBoxLayout()
    	self.setLayout(self.layout)
    	self.label = QtWidgets.QLabel()

    	self.pixmap = QPixmap('imgs/Arklogo.png')
    	splash = QtWidgets.QSplashScreen(self.pixmap)
    	splash.show()

    	time.sleep(5)
    	splash.finish(self)
    	self.label.setPixmap(self.pixmap)
    	self.label.resize(self.pixmap.width(), self.pixmap.height())
    	self.label.setAlignment(Qt.AlignCenter)
    	
    	self.label.setPixmap(self.pixmap)
    	self.label.resize(self.pixmap.width(), self.pixmap.height())
    	self.label.setAlignment(Qt.AlignCenter)
    	self.layout.addWidget(self.label)
    	
    	self.load_button = QtWidgets.QPushButton("Welcome!")
    	# self.load_button.setAlignment(Qt.AlignCenter)
    	self.load_button.setFont(QFont('Arial', 20))
    	self.load_button.clicked.connect(self.setWidgets)
    	self.layout.addWidget(self.load_button, alignment = Qt.AlignCenter)
    	
    def setWidgets(self):
    	self.label.clear()
    	self.load_button.deleteLater()
    	tabwidget = QtWidgets.QTabWidget()
    	wid = QtWidgets.QFrame()
    	wid2 = QtWidgets.QFrame()
    	wid3 = QtWidgets.QFrame()
    	wid4 = QtWidgets.QFrame()
    	tab1 = tabwidget.addTab(wid, "Text")
    	tab2 = tabwidget.addTab(wid2, "Folder")
    	tab3 = tabwidget.addTab(wid3, "Steganography")
    	tab4 = tabwidget.addTab(wid4, "Media")

    	tabwidget.setTabPosition(QtWidgets.QTabWidget.West)
    	tabwidget.setTabIcon(tab1, QIcon('imgs/text.png'))
    	tabwidget.setTabIcon(tab2, QIcon('imgs/folder.png'))
    	tabwidget.setTabIcon(tab3, QIcon('imgs/image.png'))
    	tabwidget.setTabIcon(tab4, QIcon('imgs/media.png'))
    	self.layout.addWidget(tabwidget, alignment=Qt.AlignLeft)

    	selectGroup = QtWidgets.QGroupBox(wid)
    	selectGroup.setTitle('Select Cipher')
    	self.lst = QtWidgets.QListWidget(selectGroup)
    	self.cyphers = [i for i in open('ciphers.txt').readlines()]
    	self.lst.addItems(self.cyphers)
    	
    	self.search = QtWidgets.QLineEdit()
    	btn = QtWidgets.QPushButton('search')
    	btn.clicked.connect(lambda x:[M.SearchCipher(self.search,
    	 self.lst, self.cyphers, QtWidgets.QListWidgetItem)])

    	keys = QtWidgets.QGroupBox(selectGroup)
    	keys.setTitle('Key(s)')
    	key1 = QtWidgets.QLineEdit()
    	key2 = QtWidgets.QLineEdit()
    	keyLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
    	keys.setLayout(keyLayout)
    	keyLayout.addWidget(key1)
    	keyLayout.addWidget(key2)

    	selectLayout = QtWidgets.QGridLayout()
    	selectGroup.setLayout(selectLayout)
    	selectLayout.addWidget(self.search, 0, 2, 75, 1, alignment = Qt.AlignTop)
    	selectLayout.addWidget(btn, 0, 4, 75, 1, alignment = Qt.AlignTop)
    	selectLayout.addWidget(self.lst, 6, 2, 25, 1)
    	selectLayout.addWidget(keys, 6, 4, 25, 1)

    	frameLayout = QtWidgets.QGridLayout()
    	wid.setLayout(frameLayout)
    	frameLayout.addWidget(selectGroup, 3, 3, 75, 1)

    	AboutGroup = QtWidgets.QGroupBox(wid)
    	AboutGroup.setTitle('About selected cipher')
    	ciphergroup = QtWidgets.QGroupBox(AboutGroup)
    	ciphergroup.setTitle('Selected cipher')
    	selected_cipher = QtWidgets.QLineEdit()
    	ciphergroupLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
    	ciphergroup.setLayout(ciphergroupLayout)
    	ciphergroupLayout.addWidget(selected_cipher)

    	ShowAbout = QtWidgets.QTextEdit()
    	more = QtWidgets.QPushButton('more...')
    	AboutLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
    	AboutGroup.setLayout(AboutLayout)
    	AboutLayout.addWidget(ciphergroup)
    	AboutLayout.addWidget(ShowAbout)
    	AboutLayout.addWidget(more)

    	frameLayout.addWidget(AboutGroup, 39, 3, 50, 1)

    	openGroup = QtWidgets.QGroupBox(wid)
    	openGroup.setTitle('Encrypt Text File')
    	self.fileText = QtWidgets.QLineEdit()
    	openBtn = QtWidgets.QPushButton('Open')
    	openBtn.clicked.connect(lambda x:[M.open_text(self,
    	 QtWidgets.QFileDialog.getOpenFileName,
    	  self.fileText.setText, self.output.setText)])
    	self.output = QtWidgets.QTextEdit(openGroup)

    	copy = QtWidgets.QPushButton('Copy')
    	openLayout = QtWidgets.QVBoxLayout()
    	openGroup.setLayout(openLayout)
    	openLayout.addWidget(self.fileText)
    	openLayout.addWidget(openBtn)
    	openLayout.addWidget(self.output)
    	openLayout.addWidget(copy)
    	
    	encrypt = QtWidgets.QPushButton('encrypt')
    	decrypt = QtWidgets.QPushButton('decrypt')

    	cryptoGroup = QtWidgets.QGroupBox(openGroup)
    	cryptoGroup.setTitle('cryptography')
    	cryptoLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
    	cryptoGroup.setLayout(cryptoLayout)
    	cryptoLayout.addWidget(encrypt)
    	cryptoLayout.addWidget(decrypt)

    	openLayout.addWidget(cryptoGroup)
    	frameLayout.addWidget(openGroup, 5, 60, 55, 1)

    	progressBar = QtWidgets.QProgressBar()
    	frameLayout.addWidget(progressBar, 36, 60, 55, 1)


    	FOpenGroup = QtWidgets.QGroupBox(wid2)
    	FOpenGroup.setTitle("Open Folder")
    	folder = QtWidgets.QLineEdit()
    	open_btn = QtWidgets.QPushButton('Open')
    	OpenLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
    	FOpenGroup.setLayout(OpenLayout)
    	OpenLayout.addWidget(folder)
    	OpenLayout.addWidget(open_btn)
    	FolderLayout = QtWidgets.QVBoxLayout()
    	wid2.setLayout(FolderLayout)
    	FolderLayout.addWidget(FOpenGroup)

    	KeyGroup = QtWidgets.QGroupBox(wid2)
    	KeyGroup.setTitle("Set password")
    	password_label = QtWidgets.QLabel('password:')
    	self.password = QtWidgets.QLineEdit()
    	self.check = QtWidgets.QCheckBox('Hide password')
    	self.check.stateChanged.connect(self.HidePassword)

    	KGroupLayout = QtWidgets.QGridLayout()
    	KeyGroup.setLayout(KGroupLayout)
    	KGroupLayout.addWidget(password_label, 0, 0, 1, 1)
    	KGroupLayout.addWidget(self.password, 0, 1, 1, 1)
    	KGroupLayout.addWidget(self.check, 1, 0, 1, 1)
    	FolderLayout.addWidget(KeyGroup)

    	FselectGroup = QtWidgets.QGroupBox(wid2)
    	FselectGroup.setTitle('Select Cipher')
    	self.lst_ = QtWidgets.QListWidget(FselectGroup)

    	self.Fsearch = QtWidgets.QLineEdit()
    	Fbtn = QtWidgets.QPushButton('search')
    	Fbtn.clicked.connect(lambda x:[M.SearchCipher(self.Fsearch,
    	 self.lst_, self.cyphers, QtWidgets.QListWidgetItem)])
    	#Edit Fcyphers to cyphers for folder encryption
    	# Fcyphers = [i for i in open('ciphers.txt').readlines()]
    	self.lst_.addItems(self.cyphers)
    	Fkeys = QtWidgets.QGroupBox(FselectGroup)
    	Fkeys.setTitle('Key(s)')
    	Fkey1 = QtWidgets.QLineEdit()
    	Fkey2 = QtWidgets.QLineEdit()
    	FkeyLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
    	Fkeys.setLayout(FkeyLayout)
    	FkeyLayout.addWidget(key1)
    	FkeyLayout.addWidget(key2)

    	FselectLayout = QtWidgets.QGridLayout()
    	FselectGroup.setLayout(FselectLayout)
    	FselectLayout.addWidget(self.Fsearch, 0, 2, 10, 1, alignment = Qt.AlignTop)
    	FselectLayout.addWidget(Fbtn, 0, 4, 10, 1, alignment = Qt.AlignTop)
    	FselectLayout.addWidget(self.lst_, 6, 2, 5, 1)
    	FselectLayout.addWidget(Fkeys, 6, 4, 5, 1)

    	FolderLayout.addWidget(FselectGroup)

    	FTools = QtWidgets.QGroupBox(wid2)
    	FTools.setTitle('Tools')
    	Lock = QtWidgets.QPushButton('Lock')
    	Unlock = QtWidgets.QPushButton('Remove Lock')
    	hash_sha256 = QtWidgets.QPushButton('SHA 256')
    	FtoolLayout = QtWidgets.QGridLayout()
    	FTools.setLayout(FtoolLayout)
    	FtoolLayout.addWidget(Lock, 0, 0, 2, 1)
    	FtoolLayout.addWidget(Unlock, 0, 1, 2, 1)
    	FtoolLayout.addWidget(hash_sha256, 0, 2, 2, 1)

    	FolderLayout.addWidget(FTools)

    	SteganOpenGrp = QtWidgets.QGroupBox(wid3)
    	SteganOpenGrp.setTitle("Open Image")
    	image = QtWidgets.QLineEdit()
    	openimg_btn = QtWidgets.QPushButton('Open Image')
    	OpenImgLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
    	SteganOpenGrp.setLayout(OpenImgLayout)
    	OpenImgLayout.addWidget(image)
    	OpenImgLayout.addWidget(openimg_btn)
    	SteganLayout = QtWidgets.QVBoxLayout()
    	wid3.setLayout(SteganLayout)
    	SteganLayout.addWidget(SteganOpenGrp)

    	DisplayGrp = QtWidgets.QGroupBox(wid3)
    	DisplayGrp.setTitle("Image")
    	DisplayLayout = QtWidgets.QVBoxLayout()
    	DisplayGrp.setLayout(DisplayLayout)
    	SteganLayout.addWidget(DisplayGrp)

    	TextGrp = QtWidgets.QGroupBox(wid3)
    	TextGrp.setTitle('Steganographise text')
    	text_label = QtWidgets.QLabel('Text:')
    	text = QtWidgets.QLineEdit()
    	TextGrpLayout = QtWidgets.QGridLayout()
    	TextGrp.setLayout(TextGrpLayout)
    	TextGrpLayout.addWidget(text_label, 0, 0, 1, 1)
    	TextGrpLayout.addWidget(text, 0, 1, 1, 1)
    	SteganLayout.addWidget(TextGrp)

    	SteganGrp = QtWidgets.QGroupBox(wid3)
    	SteganGrp.setTitle('steganography')
    	encrypt_btn = QtWidgets.QPushButton("encrypt")
    	decrypt_btn = QtWidgets.QPushButton("decrypt")
    	copy_btn = QtWidgets.QPushButton("copy text")
    	SteganGrpLayout = QtWidgets.QGridLayout()
    	SteganGrp.setLayout(SteganGrpLayout)
    	SteganGrpLayout.addWidget(encrypt_btn, 0, 0, 2, 1)
    	SteganGrpLayout.addWidget(decrypt_btn, 0, 1, 2, 1)
    	SteganGrpLayout.addWidget(copy_btn, 0, 2, 2, 1)
    	SteganLayout.addWidget(SteganGrp)

    def HidePassword(self):
    	self.password.setEchoMode(QtWidgets.QLineEdit.Password)
    	self.password.setStyleSheet('lineedit-password-character: 9679')
    	self.check.stateChanged.connect(self.ShowPassword)
    def ShowPassword(self):
    	# self.password.setEchoMode(QtWidgets.QLineEdit.Text)
    	return

if __name__=='__main__':
	app = QtWidgets.QApplication(sys.argv)
	win = Window()
	win.show()
	sys.exit(app.exec_())



