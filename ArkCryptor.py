# import wikipedia
import sys, time, admin
from PyQt5 import QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from backend import Methods as M
from glob import glob
from algorithms import *

class Window(QtWidgets.QWidget):
	def __init__(self):
		QtWidgets.QWidget.__init__(self)
		self.setWindowTitle("Cryptor")
		self.setGeometry(200, 100, 600, 530)
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
		dark_palette.setColor(QPalette.Disabled, QPalette.Window,
		 QColor(68, 68, 68, 255))
		dark_palette.setColor(QPalette.Disabled, QPalette.WindowText,
		 QColor(164, 166, 168, 96))
		dark_palette.setColor(QPalette.Disabled, QPalette.Text,
		 QColor(164, 166, 168, 96))
		dark_palette.setColor(QPalette.Disabled, QPalette.ButtonText,
		 QColor(164, 166, 168, 96))
		dark_palette.setColor(QPalette.Disabled, QPalette.Base,
		 QColor(68, 68, 68, 255))
		dark_palette.setColor(QPalette.Disabled, QPalette.Shadow,
		 QColor(0, 0, 0, 255))

		app.setPalette(dark_palette)
		app.setStyleSheet("QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }")
		app.setWindowIcon(QIcon('icon.png'))
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
		wid5 = QtWidgets.QFrame()
		wid6 = QtWidgets.QFrame()

		tab1 = tabwidget.addTab(wid, "Text")
		tab2 = tabwidget.addTab(wid2, "Folder")
		tab3 = tabwidget.addTab(wid3, "Steganography")
		tab4 = tabwidget.addTab(wid4, "Crack")
		tab5 = tabwidget.addTab(wid5, "Handy")
		tab6 = tabwidget.addTab(wid6, "About")

		tabwidget.setTabPosition(QtWidgets.QTabWidget.West)
		tabwidget.setTabIcon(tab1, QIcon('imgs/text.png'))
		tabwidget.setTabIcon(tab2, QIcon('imgs/folder.png'))
		tabwidget.setTabIcon(tab3, QIcon('imgs/image.png'))
		tabwidget.setTabIcon(tab4, QIcon('imgs/crack.png'))
		tabwidget.setTabIcon(tab5, QIcon('imgs/handy.png'))
		tabwidget.setTabIcon(tab6, QIcon('imgs/about.png'))

		self.layout.addWidget(tabwidget, alignment=Qt.AlignLeft)

		selectGroup = QtWidgets.QGroupBox(wid)
		selectGroup.setTitle('Select Cipher')
		self.lst = QtWidgets.QListWidget(selectGroup)
		self.cyphers = [i for i in list(eval(open('ciphers.txt').read()))]
		self.lst.addItems(self.cyphers)
		
		self.search = QtWidgets.QLineEdit()
		btn = QtWidgets.QPushButton('search')
		btn.clicked.connect(lambda x:[M.SearchCipher(self.search,
		 self.lst, self.cyphers, QtWidgets.QListWidgetItem)])

		keys = QtWidgets.QGroupBox(selectGroup)
		keys.setTitle('Key(s)')
		self.key1 = QtWidgets.QLineEdit()
		self.key2 = QtWidgets.QLineEdit()
		keyLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
		keys.setLayout(keyLayout)
		keyLayout.addWidget(self.key1)
		keyLayout.addWidget(self.key2)

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
		self.selected_cipher = QtWidgets.QLineEdit()

		ciphergroupLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
		ciphergroup.setLayout(ciphergroupLayout)
		ciphergroupLayout.addWidget(self.selected_cipher)

		self.lst.itemClicked.connect(
			lambda x:[M.SelectCipher(x, self.selected_cipher.setText)])

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
		  self.fileText.setText, self.input.setText)])
		self.input = QtWidgets.QTextEdit(openGroup)
		self.output = QtWidgets.QTextEdit(openGroup)

		copy = QtWidgets.QPushButton('Copy')
		openLayout = QtWidgets.QVBoxLayout()
		openGroup.setLayout(openLayout)
		openLayout.addWidget(self.fileText)
		openLayout.addWidget(openBtn)
		openLayout.addWidget(self.input)
		openLayout.addWidget(self.output)
		openLayout.addWidget(copy)
		
		encrypt = QtWidgets.QPushButton('encrypt')
		encrypt.clicked.connect(self.encrypt)
		decrypt = QtWidgets.QPushButton('decrypt')

		cryptoGroup = QtWidgets.QGroupBox(openGroup)
		cryptoGroup.setTitle('cryptography')
		cryptoLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		cryptoGroup.setLayout(cryptoLayout)
		cryptoLayout.addWidget(encrypt)
		cryptoLayout.addWidget(decrypt)

		openLayout.addWidget(cryptoGroup)
		frameLayout.addWidget(openGroup, 5, 60, 65, 1)

		progressBar = QtWidgets.QProgressBar()
		frameLayout.addWidget(progressBar, 36, 60, 65, 1)


		FOpenGroup = QtWidgets.QGroupBox(wid2)
		FOpenGroup.setTitle("Open Folder")
		self.folder = QtWidgets.QLineEdit()
		open_btn = QtWidgets.QPushButton('Open')
		#fix this
		open_btn.clicked.connect(lambda x:[M.OpenFolder(self, 
			QtWidgets.QFileDialog.getExistingDirectory, self.folder.setText)])
		OpenLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		FOpenGroup.setLayout(OpenLayout)
		OpenLayout.addWidget(self.folder)
		OpenLayout.addWidget(open_btn)
		FolderLayout = QtWidgets.QVBoxLayout()
		wid2.setLayout(FolderLayout)
		FolderLayout.addWidget(FOpenGroup)

		KeyGroup = QtWidgets.QGroupBox(wid2)
		KeyGroup.setTitle("Set password")
		password_label = QtWidgets.QLabel('password:')
		self.password = QtWidgets.QLineEdit()
		self.check = QtWidgets.QCheckBox('Hide password')
		self.check.stateChanged.connect(lambda:[self.HidePassword(self.password, self.check)])

		KGroupLayout = QtWidgets.QGridLayout()
		KeyGroup.setLayout(KGroupLayout)
		KGroupLayout.addWidget(password_label, 0, 0, 1, 1)
		KGroupLayout.addWidget(self.password, 0, 1, 1, 1)
		KGroupLayout.addWidget(self.check, 1, 0, 1, 1)
		FolderLayout.addWidget(KeyGroup)

		FselectGroup = QtWidgets.QGroupBox(wid2)
		FselectGroup.setTitle('View Folders')
		# model = QtWidgets.QFileSystemModel()
		# model.setRootPath('')
		# self.lst_ = QtWidgets.QTreeView()
		self.lst_ = QtWidgets.QListWidget(FselectGroup)
		self.lst_.addItems(i.replace('\n', '') for i in open('HiddenFiles.{21EC2020-3AEA-1069-A2DD-08002B30309D}').readlines())

		# self.lst_.setModel(model)
		# self.lst_.setAnimated(False)
		# self.lst_.setIndentation(20)
		# self.lst_.setSortingEnabled(True)

		F1 = QtWidgets.QLabel('/'*124)
		F2 = QtWidgets.QLabel('\\'*124)
		# self.foldrs = [i for i in glob("")]
		# self.lst_.addItems(self.foldrs)
		Fsha = QtWidgets.QGroupBox(FselectGroup)
		Fsha.setTitle('SHA-256')
		FShaView = QtWidgets.QTextEdit()
		FCopyBtn = QtWidgets.QPushButton('copy')
		FkeyLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
		Fsha.setLayout(FkeyLayout)
		FkeyLayout.addWidget(FShaView)
		FkeyLayout.addWidget(FCopyBtn)

		FselectLayout = QtWidgets.QGridLayout()
		FselectGroup.setLayout(FselectLayout)
		FselectLayout.addWidget(F1, 0, 2, 10, 1, alignment = Qt.AlignTop)
		FselectLayout.addWidget(F2, 0, 4, 10, 1, alignment = Qt.AlignTop)
		FselectLayout.addWidget(self.lst_, 6, 2, 5, 1)
		FselectLayout.addWidget(Fsha, 6, 4, 5, 1)

		FolderLayout.addWidget(FselectGroup)

		FTools = QtWidgets.QGroupBox(wid2)
		FTools.setTitle('Tools')
		Lock = QtWidgets.QPushButton('Lock')
		Lock.clicked.connect(lambda x:[M.Lock(self.password.text(),
			self.folder.text(),'L')])
		Unlock = QtWidgets.QPushButton('Unlock')
		Unlock.clicked.connect(lambda x:[M.Lock(self.password.text(),
			self.folder.text(), 'U')])
		change = QtWidgets.QPushButton('Change')
		change.clicked.connect(lambda x:[M.Lock(self.password.text(),
			self.folder.text(), 'U')])
		forgot = QtWidgets.QPushButton('Forgot')
		hash_sha256 = QtWidgets.QPushButton('SHA 256')
		hash_sha256.clicked.connect(lambda x:[M.genHash(folder.text(),
		 FShaView.setText)])
		# openimg_btn.clicked.connect(lambda x :[M.OpenImage(self, 
		# 	QtWidgets.QFileDialog.getOpenFileName, image.setText, QtWidgets.QLabel,
		# 	QPixmap, DisplayLayout)])

		FtoolLayout = QtWidgets.QGridLayout()
		FTools.setLayout(FtoolLayout)
		FtoolLayout.addWidget(Lock, 0, 0, 2, 1)
		FtoolLayout.addWidget(Unlock, 0, 1, 2, 1)
		FtoolLayout.addWidget(change, 0, 2, 2, 1)
		FtoolLayout.addWidget(forgot, 0, 3, 2, 1)
		FtoolLayout.addWidget(hash_sha256, 0, 4, 2, 1)

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

		openimg_btn.clicked.connect(lambda x :[M.OpenImage(self, 
			QtWidgets.QFileDialog.getOpenFileName, image.setText,
			QtWidgets.QLabel, QPixmap, DisplayLayout)])

		TextGrp = QtWidgets.QGroupBox(wid3)
		TextGrp.setTitle('Steganographise text')
		text_label = QtWidgets.QLabel('Text:')
		text = QtWidgets.QLineEdit()
		
		HidTxtInImg = QtWidgets.QRadioButton("Hide text in viewable image")
		TxtInImg = QtWidgets.QRadioButton("Hide text in unviewable image")
		OutBtn = QtWidgets.QPushButton('////'*200)
		OutBtn.setFlat(True)
		oUtPuT = QtWidgets.QLineEdit()

		TextGrpLayout = QtWidgets.QGridLayout()
		TextGrp.setLayout(TextGrpLayout)
		TextGrpLayout.addWidget(text_label, 0, 0, 1, 1)
		TextGrpLayout.addWidget(text, 0, 1, 1, 1)
		TextGrpLayout.addWidget(HidTxtInImg, 0, 2, 1,2)
		TextGrpLayout.addWidget(TxtInImg, 1, 2, 1, 2)
		TextGrpLayout.addWidget(OutBtn, 1, 0, 1, 2)
		SteganLayout.addWidget(TextGrp)

		SteganGrp = QtWidgets.QGroupBox(wid3)
		SteganGrp.setTitle('steganography')
		encrypt_btn = QtWidgets.QPushButton("encrypt")
		encrypt_btn.clicked.connect(lambda x:[M.encodeSteganography(
			TxtInImg.isChecked(), image.text(), text.text(), 
			QtWidgets.QFileDialog.getNewFileName(self, 'Save As', '*.jpg'))])
		decrypt_btn = QtWidgets.QPushButton("decrypt")
		decrypt_btn.clicked.connect(lambda x:[M.decodeSteganography(
			TxtInImg.isChecked(), image.text(), text.text())])
		paste_btn = QtWidgets.QPushButton("paste text")
		SteganGrpLayout = QtWidgets.QGridLayout()
		SteganGrp.setLayout(SteganGrpLayout)
		SteganGrpLayout.addWidget(encrypt_btn, 0, 0, 2, 1)
		SteganGrpLayout.addWidget(decrypt_btn, 0, 1, 2, 1)
		SteganGrpLayout.addWidget(paste_btn, 0, 2, 2, 1)
		SteganLayout.addWidget(SteganGrp)


		#====================Cr@ck T@b R3G!0N==================
		CrackGrp = QtWidgets.QGroupBox()
		CrackGrp.setTitle("$tuff2Cr@ck")
		
		OpenGrp = QtWidgets.QGroupBox(CrackGrp)
		OpenGrp.setTitle("Open Text")
		openedFile = QtWidgets.QLineEdit()
		openButton = QtWidgets.QPushButton("Open")

		OpenGrpLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		OpenGrp.setLayout(OpenGrpLayout)
		OpenGrpLayout.addWidget(openedFile)
		OpenGrpLayout.addWidget(openButton)

		SelectGrp = QtWidgets.QGroupBox(CrackGrp)
		SelectGrp.setTitle('Select Cipher')
		self._lst_ = QtWidgets.QListWidget(SelectGrp)
		self._lst_.addItems(self.cyphers)		
		self._search_ = QtWidgets.QLineEdit()
		_btn_ = QtWidgets.QPushButton('search')
		_btn_.clicked.connect(lambda x:[M.SearchCipher(self.search,
		 self._lst_, self.cyphers, QtWidgets.QListWidgetItem)])
		SelectGrpLayout = QtWidgets.QGridLayout()
		SelectGrp.setLayout(SelectGrpLayout)
		SelectGrpLayout.addWidget(self._search_, 0, 0, 1, 1)
		SelectGrpLayout.addWidget(_btn_, 0, 1, 1, 1)
		SelectGrpLayout.addWidget(self._lst_, 1, 0, 1, 2)

		crack_btn = QtWidgets.QPushButton("Crack")

		CipherGrp = QtWidgets.QGroupBox(CrackGrp)
		CipherGrp.setTitle("Cipher text")
		Ciphertext = QtWidgets.QTextEdit()
		CipherGrpLayout = QtWidgets.QGridLayout()
		CipherGrp.setLayout(CipherGrpLayout)
		CipherGrpLayout.addWidget(Ciphertext)

		CrackedGrp = QtWidgets.QGroupBox(CrackGrp)
		CrackedGrp.setTitle("Cracked Text")
		Crackedtext = QtWidgets.QTextEdit()
		copy_btn = QtWidgets.QPushButton("Copy")
		CrackedGrpLayout = QtWidgets.QGridLayout()
		CrackedGrp.setLayout(CrackedGrpLayout)
		CrackedGrpLayout.addWidget(Crackedtext)
		CrackedGrpLayout.addWidget(copy_btn)

		CrackGrpLayout = QtWidgets.QGridLayout()
		CrackGrp.setLayout(CrackGrpLayout)
		CrackGrpLayout.addWidget(OpenGrp)
		CrackGrpLayout.addWidget(SelectGrp)
		CrackGrpLayout.addWidget(crack_btn)
		
		OutputGrp = QtWidgets.QGroupBox()
		OutputGrp.setTitle("0utput")
		OutputLayout = QtWidgets.QGridLayout()
		OutputGrp.setLayout(OutputLayout)
		OutputLayout.addWidget(CipherGrp)
		OutputLayout.addWidget(CrackedGrp)
		OutputLayout.addWidget(copy_btn)

		wid4Layout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		wid4.setLayout(wid4Layout)
		wid4Layout.addWidget(CrackGrp)
		wid4Layout.addWidget(OutputGrp)

		#================= Handy Tab Region ================
		PassTestGrp = QtWidgets.QGroupBox()
		PassTestGrp.setTitle("Password Test")
		pwdGrp = QtWidgets.QGroupBox()
		pwdGrp.setTitle("Password")
		pwd_label = QtWidgets.QLabel("Enter Password:")
		self.pwd_entry = QtWidgets.QLineEdit()
		self.pwd_check = QtWidgets.QCheckBox('Hide Password')
		self.pwd_check.stateChanged.connect(lambda:[self.HidePassword(self.pwd_entry, self.pwd_check)])

		info_label_frame = QtWidgets.QGroupBox()
		info_label_frame.setTitle("Password info")
		Password_info = QtWidgets.QTextEdit()
		labframeLayout = QtWidgets.QGridLayout()
		info_label_frame.setLayout(labframeLayout)
		labframeLayout.addWidget(Password_info)

		pwdGrpLayout = QtWidgets.QGridLayout()
		pwdGrp.setLayout(pwdGrpLayout)
		pwdGrpLayout.addWidget(pwd_label, 0, 0, 1, 1)
		pwdGrpLayout.addWidget(self.pwd_entry, 0, 1, 1, 1)
		pwdGrpLayout.addWidget(self.pwd_check, 1, 0, 1, 1)

		PassTestGrpLayout = QtWidgets.QGridLayout()
		PassTestGrp.setLayout(PassTestGrpLayout)
		PassTestGrpLayout.addWidget(pwdGrp)
		PassTestGrpLayout.addWidget(info_label_frame)

		Border = QtWidgets.QLabel("|\n"*1002)

		BaseConvertGrp = QtWidgets.QGroupBox()
		BaseConvertGrp.setTitle("Convert Bases")
		
		slct_numGrp = QtWidgets.QGroupBox()
		slct_numGrp.setTitle("Put in No.")
		self.slct_num = QtWidgets.QSpinBox()
		slct_numGrpLayout = QtWidgets.QGridLayout()
		slct_numGrp.setLayout(slct_numGrpLayout)
		slct_numGrpLayout.addWidget(self.slct_num)

		NoBaseGrp = QtWidgets.QGroupBox()
		base_label1 = QtWidgets.QLabel("Selected Number Base:")
		self.number_base = QtWidgets.QSpinBox()
		_border_ = QtWidgets.QLabel("--"*25)

		NoBaseGrpLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		NoBaseGrp.setLayout(NoBaseGrpLayout)
		NoBaseGrpLayout.addWidget(base_label1)
		NoBaseGrpLayout.addWidget(self.number_base)

		ConvertBaseGrp = QtWidgets.QGroupBox()
		base_label2 = QtWidgets.QLabel("Convert To Base:")
		self.convert_base = QtWidgets.QSpinBox()
		ConvertBaseLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		ConvertBaseGrp.setLayout(ConvertBaseLayout)
		ConvertBaseLayout.addWidget(base_label2)
		ConvertBaseLayout.addWidget(self.convert_base)

		output_label_frame = QtWidgets.QGroupBox()
		output_label_frame.setTitle("Base Output")
		BaseOutput = QtWidgets.QTextEdit()
		BtnGrp = QtWidgets.QGroupBox()
		convert_btn = QtWidgets.QPushButton("Convert")
		copy_btn1 = QtWidgets.QPushButton("Copy")
		BtnGrpLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		BtnGrp.setLayout(BtnGrpLayout)
		BtnGrpLayout.addWidget(convert_btn)
		BtnGrpLayout.addWidget(copy_btn1)
		BlabframeLayout = QtWidgets.QGridLayout()
		output_label_frame.setLayout(BlabframeLayout)
		BlabframeLayout.addWidget(BaseOutput)
		BlabframeLayout.addWidget(BtnGrp)

		BaseLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
		BaseConvertGrp.setLayout(BaseLayout)
		BaseLayout.addWidget(slct_numGrp)
		BaseLayout.addWidget(NoBaseGrp)
		BaseLayout.addWidget(_border_)
		BaseLayout.addWidget(ConvertBaseGrp)
		BaseLayout.addWidget(output_label_frame)


		wid5Layout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		wid5.setLayout(wid5Layout)
		wid5Layout.addWidget(PassTestGrp)
		wid5Layout.addWidget(Border)
		wid5Layout.addWidget(BaseConvertGrp)

	def HidePassword(self, password, check):
		if check.isChecked():
			password.setEchoMode(QtWidgets.QLineEdit.Password)
			password.setStyleSheet('lineedit-password-character: 9679')
		if not check.isChecked():
			password.setEchoMode(QtWidgets.QLineEdit.Normal)

	def encrypt(self):
		data = open(self.fileText.text(), 'r').read()
		dct = eval(open('ciphers.txt', 'r').read())
		k1, k2 = int(self.key1.text()), int(self.key2.text())
		print(type(int(self.key1.text())))
		# print(dct[self.selected_cipher.text()])
		self.output.setText(eval(dct[self.selected_cipher.text()])(k1, data))


if __name__=='__main__':
	# if not admin.isUserAdmin():
		# admin.runAsAdmin()
	app = QtWidgets.QApplication(sys.argv)
	win = Window()
	win.show()
	sys.exit(app.exec_())



