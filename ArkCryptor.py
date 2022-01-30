#!/bin/python3

import sys, time, admin, wikipedia
from PyQt5 import QtWidgets
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5 import QtGui
from backend import Methods as M
# from glob import glob
from algorithms import *
from stegan import *
from PIL import Image, ImageDraw
from BaseCipher import BaseCipher
import crack, crypta, hasher
from TextEditor import TextEditor
from datetime import datetime as dt
from random import shuffle
from os import chdir, mkdir, getcwd
from base_funcs import *
from crypta import *


ciphers_list = {
	'KRIS' : ('KRIS-AES-256', 'KRIS-AES-192', 'KRIS-AES-128'),

	'AES' : ('AES-256', 'AES-192', 'AES-128'),

	'RSA' : ('RSA', ('RSA signature')),

	'Crypta' : tuple(crypta.crypta_ciphers.keys()),

	('analysis') : (('Text analysis'), ('Frequence analysis'), ('Index of coincidence'), \
		('Kasiki examination'), ("Friedman's test")),

	'hash' : hasher.h_str + ('SecHash',)
}
# Edit this crack section to suite your needs
#---------Crack
class UseCrackTab:
	'''Class which allow to use the Crack tab.'''

	# use_crack = UseCrackTab(args)
	# ...
	# bt_crack.clicked.connect(use_crack.crack)

	def __init__(self, txt, opt_algo, opt_meth, wlst_sp, wlst_alf, wrdlst, txt_ret):
		'''Create the UseCrackTab object.'''

		self.txt = txt
		self.opt_algo = opt_algo
		self.opt_meth = opt_meth
		self.wlst_sp = wlst_sp
		self.wlst_alf = wlst_alf
		self.wrdlst = wrdlst
		self.txt_ret = txt_ret


	def _verify(self):
		'''Check if everything is filled, raise a popup and return -3 else.'''

		if self.opt_algo.currentText() == None:
			QtWidgets.QMessageBox.critical(None, '!!! No algo selected !!!', '<h2>Please select an algorithm !!!</h2>')
			return -3

		if self.opt_meth.currentText() == '-- Select a method --':
			QtWidgets.QMessageBox.critical(None, '!!! No method selected !!!', '<h2>Please select a crack method !!!</h2>')
			return -3


		if self.opt_meth.currentText() == 'Brute-force' and self.wlst_alf.currentText() == ('-- Select an alphabet --'):
			QtWidgets.QMessageBox.critical(None, '!!! No alphabet selected !!!', '<h2>Please select an alphabet !!!</h2>')
			return -3

		if self.opt_meth.currentText() == 'Dictionary attack' and self.wrdlst.currentText() == '-- Previously selected wordlists --':
			QtWidgets.QMessageBox.critical(None, '!!! No wordlist selected !!!', '<h2>Please select a wordlist !!!</h2>')
			return -3


	def _ret_append(self, txt, algo=None):
		'''Append 'txt' to the ret QTextEdit, adding some info behind.'''

		meth = self.opt_meth.currentText()
		if algo == None:
			algo = self.opt_algo.currentText()

		sep = ('\n' + '―'*20 + '\n', '')[self.txt_ret.toPlainText() == '']

		self.txt_ret.append(
			'{}{} - {} on {} : {}\n'.format(
				sep,
				str(dt.now())[:-7],
				meth,
				algo,
				txt
			)
		)


	def _crack(self, C, msg_f, prnt, t0, algo=None, f_verbose=True):
		'''Try to crack the text.'''

		txt = self.txt.getText()
		meth = self.opt_meth.currentText()
		wlst_lth = self.wlst_sp.value()
		wlst_alf = self.wlst_alf.currentText()
		self.wrdlst = self.wrdlst.currentText()

		if algo == None:
			algo = self.opt_algo.currentText()

		pwd = False

		if meth == 'Brute-force':
			if algo in ciphers_list['hash'] + crypta.ciph_sort['0_key']:
				pwd = crack.SmartBruteForce(
					C
				).permutation(txt, wlst_lth, wlst_alf)

			elif algo in crypta.ciph_sort['1_key_str']:
				#------check the alphabet, to know if there is numbers in
				for k in wlst_alf:
					if k in '0123456789':
						QtWidgets.QMessageBox.warning(None, 'Useless !', '<h2>There is at least one number in your alphabet, but that\'s useless since the cipher only takes string keys.</h2>')
						return -3

				brk = crack.SmartBruteForce(C).brute_force_str(wlst_lth, wlst_alf, str, ldm=True)

				self._ret_append(brk, algo)

			elif algo in crypta.ciph_sort['1_key_int']:
				#------check the alphabet
				for k in wlst_alf:
					if k not in '0123456789':
						QtWidgets.QMessageBox.warning(None, 'Useless !', '<h2>There is at least one character which is not a number in your alphabet, so that\'s useless since the cipher only takes numbers keys.</h2>')
						return -3

				brk = crack.SmartBruteForce(C).brute_force_str(wlst_lth, wlst_alf, int, ldm=True)

				self._ret_append(brk, algo)

		elif meth == 'Dictionary attack':
			pwd = crack.BruteForce(C, self.wrdlst).crack(txt)

		elif meth == 'Advanced brute-force':
			pwd = crack.SmartBruteForce(C).crack(txt)


		if pwd == False:
			pass

		elif pwd == None:
			self._ret_append(msg_f, algo)
			if f_verbose:
				QtWidgets.QMessageBox.warning(
					None, 'Not found !',
					'<h2>The clear text has not be found !!!</h2>\n<h3>Try with an other {}, method, or dictionary.</h3>'.format(prnt)
				)

		else:
			self._ret_append('\n\t{}.'.format(NewLine(c='\n\t').set('{} ===> {}'.format(pwd, txt))), algo)
			QtWidgets.QMessageBox.about(
				None, '{} cracked !!!'.format(prnt),
				'<h2>The {} has been be cracked in {}s !<h2>\n<h2>result :</h2><h1>{}</h1>'.format(
					prnt,
					dt.now() - t0,
					pwd
				)
			)

			return pwd


	def crack(self):
		'''Method which use the Crack tab, when "Crack" button is pressed.'''

		if self._verify() == -3:
			return -3 #Abort

		txt = self.txt.getText()
		algo = self.opt_algo.currentText()
		meth = self.opt_meth.currentText()
		wlst_lth = self.wlst_sp.value()
		wlst_alf = self.wlst_alf.currentText()
		self.wrdlst = self.wrdlst.currentText()

		msg_f = '\n\tThe clear text has not be found.' #Message False (not found)

		t0 = dt.now()

		if algo not in ('Unknown', 'Unknown hash'):
			#------get the encryption function
			if algo in ciphers_list['hash']:
				C = hasher.Hasher(algo).hash
				prnt = 'hash'

			elif algo in crypta.ciph_sort['0_key']:
				C = crypta.make_ciph(algo).encrypt
				prnt = 'cipher'

			elif algo in (*crypta.ciph_sort['1_key_int'], *crypta.ciph_sort['1_key_str']):
				C = lambda key: crypta.crypta_ciphers[algo](key).decrypt(txt)
				prnt = 'cipher'


			if meth in ('Brute-force', 'Dictionary attack', 'Advanced brute-force'):
				ret = self._crack(C, msg_f, prnt, t0)
				if ret == -3:
					return -3


			elif meth == 'Code break':
				C = crypta.make_ciph(algo)

				if algo in crypta.broken_ciph_dict['break_']:
					try:
						brk = C.break_(txt)

					except Exception as ept:
						QtWidgets.QMessageBox.critical(None, '!!! Error !!!', '<h2>{}</h2>'.format(ept))
						return -3

					self._ret_append('\n\t{}'.format(NewLine(c='\n\t').set('{} ===> {}'.format(brk, txt))))

				else:
					brk = C.brute_force(txt)
					m = C.meaning(txt, brk)

					if m[0] == False:
						answer = QtWidgets.QMessageBox.question(
							None, 'Maybe not found',
							'<h2>The list of broken word does not seem to contain something which makes sense.</h2>\n<h2>Show the list anyway ?</h2>',
							QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.No
						)

						if answer == QtWidgets.QMessageBox.Yes:
							ret = 'Possible decryptions (key - decryption) :'
							for k in brk:
								ret += '\n\t{} - {}'.format(k, brk[k])

							self._ret_append(ret)

						else:
							self._ret_append(msg_f)

					else:
						self._ret_append('\n\t{}'.format(NewLine(c='\n\t').set('{} ===> {}'.format(m, txt)))) #todo: improve this return : it just show the list (True, txt_c, [key, [alf]])


		elif algo == 'Unknown':
			pos_algo = crack.deter(txt)

			if pos_algo == ():
				QtWidgets.QMessageBox.critical(None, 'Cipher not found !!!', '<h2>It is impossible to identify the cipher !!!</h2>')
				return -3

			self._ret_append('\nPossibles used algorithms :' + set_lst(pos_algo))

			rep = QtWidgets.QMessageBox.question(None, 'Crack ?', '<h2>Try to crack these ciphers ?</h2>', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.Yes)

			if rep == QtWidgets.QMessageBox.No:
				return -3

			for k in pos_algo:
				if k in ciphers_list['hash']:
					C = hasher.Hasher(k).hash
					prnt = 'hash'

				elif k in crypta.ciph_sort['0_key']:
					C = crypta.make_ciph(k).encrypt
					prnt = 'cipher'

				elif k in (*crypta.ciph_sort['1_key_int'], *crypta.ciph_sort['1_key_str']):
					C = lambda key: crypta.crypta_ciphers[k](key).decrypt(txt)
					prnt = 'cipher'

				else:
					C = None
					prnt = None
					print('Not trying to crack with the {} cipher.'.format(k))


				if C != None:
					print(k)
					ret = self._crack(C, msg_f, prnt, t0, algo=k, f_verbose=False)

					if ret not in (-3, None):
						break


		else: #algo == 'Unknown hash'
			pos_hash = crack.deter(txt, only_hash=True)

			if pos_hash == ():
				QtWidgets.QMessageBox.critical(None, 'Hash not found !!!', '<h2>It is impossible to identify the hash !!!</h2>')
				return -3

			self._ret_append('\nPossibles used hashes :' + set_lst(pos_hash))

			rep = QtWidgets.QMessageBox.question(None, 'Crack ?', '<h2>Try to crack these hashes ?</h2>', QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No, QtWidgets.QMessageBox.Yes)

			if rep == QtWidgets.QMessageBox.No:
				return -3

			for k in pos_hash:
				print(k)
				C = hasher.Hasher(k).hash
				ret = self._crack(C, msg_f, 'hash', t0, algo=k, f_verbose=False)

				if ret not in (-3, None):
					break


class Window(QtWidgets.QWidget):
	def __init__(self):
		QtWidgets.QWidget.__init__(self)
		self.setWindowTitle("X-Krypt")
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
		selectLayout.addWidget(keys, 6, 6, 25, 1)

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


		def getMore():
			# Quick func
			try:
				import webbrowser
				webbrowser.open("www.wikipedia.com/"+str(self.selected_cipher.text()))
			except Exception as e:
				QtWidgets.QMessageBox().setText(str(e))

		ShowAbout = QtWidgets.QTextEdit()
		more = QtWidgets.QPushButton('more...')
		more.clicked.connect(lambda:[getMore()])
		AboutLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
		AboutGroup.setLayout(AboutLayout)
		AboutLayout.addWidget(ciphergroup)
		AboutLayout.addWidget(ShowAbout)
		AboutLayout.addWidget(more)

		def selectThis():
			# Quick func
			try:
				ShowAbout.setText(wikipedia.summary(self.selected_cipher.text(),
					sentences=5))
			except Exception as e:
				QtWidgets.QMessageBox().setText(str(e))


		#-todo- insert wikipedia.summary in ShowAbout when you can get its text
		self.lst.itemClicked.connect(lambda x:[M.SelectCipher(x, self.selected_cipher.setText), selectThis()])
		self.lst.setFixedSize(200, 180)


		frameLayout.addWidget(AboutGroup, 59, 3, 50, 1)

		openGroup = QtWidgets.QGroupBox(wid)
		openGroup.setTitle('Encrypt Text File')
		self.fileText = QtWidgets.QLineEdit()
		openBtn = QtWidgets.QPushButton('Open')
		openBtn.clicked.connect(lambda x:[M.open_text(self,
			QtWidgets.QFileDialog.getOpenFileName,
			self.fileText.setText, self.input.setText)])
		self.input = QtWidgets.QTextEdit(openGroup)
		self.input.setPlaceholderText("Input coming from the text file")
		self.input.setFixedSize(200, 130)
		self.output = QtWidgets.QTextEdit(openGroup)
		self.output.setFixedSize(200, 130)
		self.output.setPlaceholderText("Decryption output text")

		copy = QtWidgets.QPushButton('Copy')
		copy.clicked.connect(lambda :[
			self.Copy2Clipboard(self.output.toPlainText())])
		openLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
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
		frameLayout.addWidget(openGroup, 4, 60, 105, 1)

		# progressBar = QtWidgets.QProgressBar()
		# frameLayout.addWidget(progressBar, 36, 60, 65, 1)

		#=============== Folder locking region ===============

		FOpenGroup = QtWidgets.QGroupBox(wid2)
		FOpenGroup.setTitle("Open Folder")
		self.folder = QtWidgets.QLineEdit()
		open_btn = QtWidgets.QPushButton('Open')
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
		self.check.stateChanged.connect(lambda:[
			self.HidePassword(self.password, self.check)])

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
		FCopyBtn.clicked.connect(FShaView.copy)
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
		Lock.clicked.connect(lambda x:[self.folderLock(self.password.text(),
			self.folder.text(),'L')])
		Unlock = QtWidgets.QPushButton('Unlock')
		Unlock.clicked.connect(lambda x:[self.folderLock(self.password.text(),
			self.folder.text(), 'U')])
		change = QtWidgets.QPushButton('Change')
		change.clicked.connect(lambda x:[self.folderLock(self.password.text(),
			self.folder.text(), 'U')])
		forgot = QtWidgets.QPushButton('Forgot')
		hash_sha256 = QtWidgets.QPushButton('SHA 256')
		hash_sha256.clicked.connect(lambda x:[M.genHash(self.folder.text(),
		 FShaView.setText)])

		FtoolLayout = QtWidgets.QGridLayout()
		FTools.setLayout(FtoolLayout)
		FtoolLayout.addWidget(Lock, 0, 0, 2, 1)
		FtoolLayout.addWidget(Unlock, 0, 1, 2, 1)
		FtoolLayout.addWidget(change, 0, 2, 2, 1)
		FtoolLayout.addWidget(forgot, 0, 3, 2, 1)
		FtoolLayout.addWidget(hash_sha256, 0, 4, 2, 1)

		FolderLayout.addWidget(FTools)

		SteganOpenGrp = QtWidgets.QGroupBox(wid3)
		#Text for steganography is advised to be encrypted before performing
		# steganography with X-Krypt, The text in image can be accessible by
		# anyone with X-Krypt, so it's safer to encrypt the text to make sure
		# only who you want can read it.
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

		# pwordGrp = QtWidgets.QGroupBox(wid3)
		# pword_label = QtWidgets.QLabel("Enter Password:")
		# self.pword_entry = QtWidgets.QLineEdit()
		# self.pword_check = QtWidgets.QCheckBox('Hide Password')
		# self.pword_check.stateChanged.connect(lambda:[self.HidePassword(self.pwd_entry, self.pwd_check)])

		# pwordLayout = QtWidgets.QGridLayout()
		# pwordGrp.setLayout(pwordLayout)
		# pwordLayout.addWidget(pword_label, 0, 0, 1, 1)
		# pwordLayout.addWidget(self.pword_entry, 0, 1, 1, 1)
		# pwordLayout.addWidget(self.pword_check, 1, 0, 1, 1)

		# SteganLayout.addWidget(pwordGrp)

		ViewGrp = QtWidgets.QGroupBox(wid3)
		ViewGrp.setTitle("Image view")
		ViewLayout = QtWidgets.QGridLayout()
		ViewGrp.setLayout(ViewLayout)
		SteganLayout.addWidget(ViewGrp)

		openimg_btn.clicked.connect(lambda x :[M.OpenImage(self, 
			QtWidgets.QFileDialog.getOpenFileName, image.setText,
			QtWidgets.QLabel, QPixmap, ViewLayout)])

		TextGrp = QtWidgets.QGroupBox(wid3)
		TextGrp.setTitle('Steganographise text')
		text_label = QtWidgets.QLabel('Text:')
		text = QtWidgets.QLineEdit()
		
		# HidTxtInImg = QtWidgets.QRadioButton("Hide text in viewable image")
		# TxtInImg = QtWidgets.QRadioButton("Hide text in unviewable image")
		OutBtn = QtWidgets.QLabel('////'*200)
		# OutBtn.setFlat(True)
		oUtPuT = QtWidgets.QLineEdit()

		TextGrpLayout = QtWidgets.QGridLayout()
		TextGrp.setLayout(TextGrpLayout)
		TextGrpLayout.addWidget(text_label, 0, 0, 1, 1)
		TextGrpLayout.addWidget(text, 0, 1, 1, 1)
		# TextGrpLayout.addWidget(HidTxtInImg, 0, 2, 1,2)
		# TextGrpLayout.addWidget(TxtInImg, 1, 2, 1, 2)
		TextGrpLayout.addWidget(OutBtn, 1, 0, 1, 2)
		SteganLayout.addWidget(TextGrp)

		SteganGrp = QtWidgets.QGroupBox(wid3)
		SteganGrp.setTitle('steganography')
		encrypt_btn = QtWidgets.QPushButton("encrypt")
		encrypt_btn.clicked.connect(lambda x:[encode(image.text(), text.text(),
			QtWidgets.QFileDialog.getSaveFileName(wid3, 'Save As')[0])])
		decrypt_btn = QtWidgets.QPushButton("decrypt")
		decrypt_btn.clicked.connect(lambda x:[decode(image.text(), text)])
		copy_stegan = QtWidgets.QPushButton("copy text")
		copy_stegan.clicked.connect(oUtPuT.copy)
		paste_btn = QtWidgets.QPushButton("paste text")
		SteganGrpLayout = QtWidgets.QGridLayout()
		SteganGrp.setLayout(SteganGrpLayout)
		SteganGrpLayout.addWidget(encrypt_btn, 0, 0, 2, 1)
		SteganGrpLayout.addWidget(decrypt_btn, 0, 1, 2, 1)
		SteganGrpLayout.addWidget(copy_stegan, 0, 2, 2, 1)
		SteganGrpLayout.addWidget(paste_btn, 0, 3, 2, 1)
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
		# self.cipher_ = QtWidgets.QTextEdit()
		self.cipher_ = QtWidgets.QComboBox()
		self.cipher_.addItems(['Unknown', 'Unknown hash'])
		# self.cipher_.addItems([""])

		def selectDciph(text):
			# quick func
			self.cipher_.addItems([f"{text}"])

		self._lst_.itemClicked.connect(
			lambda x:[M.SelectCipher(x, selectDciph)])

		self.method = QtWidgets.QComboBox()
		self.method.addItems(["-- Select a method --", "Brute-force",
		 "Dictionary attack", "Advanced brute-force", "Code break"])
		self.wrd_alphs = QtWidgets.QComboBox()
		self.wrd_alphs.addItems(["-- Select text context --", "01",
			"0123456789", "0123456789abcdef",
			"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"abcdefghijklmnopqrstuvwxyz0123456789",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
			""" !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~£§¨°²µ’€""",
			"""abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~£§¨°²µ’€"""
			])
		self.wrd_alphs.setFixedSize(250, 20)
		wrd_lengthbox = QtWidgets.QGroupBox(SelectGrp)
		len_label = QtWidgets.QLabel("Words' length:")
		wrd_length = QtWidgets.QSpinBox()
		wrd_length.setMinimum(1)
		lenGrpLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		wrd_lengthbox.setLayout(lenGrpLayout)
		lenGrpLayout.addWidget(len_label)
		lenGrpLayout.addWidget(wrd_length)

		wrdGrp = QtWidgets.QGroupBox()
		wrdGrp.setTitle("Wordlist")

		# self.wrdlst = QtWidgets.QPushButton("Open wordlist")
		self.wrdlstbtn = QtWidgets.QPushButton('Open')
		self.wrdlst = QtWidgets.QComboBox()
		# self.wrdlst.addItems([""])
		self.wrdlst.setFixedSize(230, 20)
		def selectIt(text):
			# quick func
			self.wrdlst.addItems([f"{text}"])
		self.wrdlstbtn.clicked.connect(lambda x:[M.open_text(self,
			QtWidgets.QFileDialog.getOpenFileName,
			selectIt, Ciphertext.setText)])
		wrdGrpLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		wrdGrp.setLayout(wrdGrpLayout)
		wrdGrpLayout.addWidget(self.wrdlst)
		wrdGrpLayout.addWidget(self.wrdlstbtn)

		SelectGrpLayout = QtWidgets.QGridLayout()
		SelectGrp.setLayout(SelectGrpLayout)
		SelectGrpLayout.addWidget(self._search_, 0, 0, 1, 1)
		SelectGrpLayout.addWidget(_btn_, 0, 1, 1, 1)
		SelectGrpLayout.addWidget(self._lst_, 1, 0, 1, 2)
		SelectGrpLayout.addWidget(self.method, 2, 0, 1, 2)
		SelectGrpLayout.addWidget(self.wrd_alphs, 3, 0, 1, 2)
		SelectGrpLayout.addWidget(wrdGrp, 4, 0, 1, 2)
		SelectGrpLayout.addWidget(self.cipher_, 5, 0, 1, 2)
		SelectGrpLayout.addWidget(wrd_lengthbox)

		crack_btn = QtWidgets.QPushButton("Crack")

		CipherGrp = QtWidgets.QGroupBox(CrackGrp)
		CipherGrp.setTitle("Cipher text")
		# Ciphertext = QtWidgets.QTextEdit()
		Ciphertext = TextEditor()
		CipherGrpLayout = QtWidgets.QGridLayout()
		CipherGrp.setLayout(CipherGrpLayout)
		CipherGrpLayout.addWidget(Ciphertext)

		CrackedGrp = QtWidgets.QGroupBox(CrackGrp)
		CrackedGrp.setTitle("Cracked Text")
		Crackedtext = QtWidgets.QTextEdit()
		copy_btn = QtWidgets.QPushButton("Copy")
		copy_btn.clicked.connect(Crackedtext.copy)
		CrackedGrpLayout = QtWidgets.QGridLayout()
		CrackedGrp.setLayout(CrackedGrpLayout)
		CrackedGrpLayout.addWidget(Crackedtext)
		CrackedGrpLayout.addWidget(copy_btn)

		openButton.clicked.connect(lambda x:[M.open_text(self,
			QtWidgets.QFileDialog.getOpenFileName,
			openedFile.setText, Ciphertext.setText)])

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

		crack_btn.clicked.connect(lambda:[UseCrackTab(txt=Ciphertext,
			opt_algo=self.cipher_, opt_meth=self.method, wlst_sp = wrd_length,
			wlst_alf=self.wrd_alphs, wrdlst=self.wrdlst, txt_ret=Crackedtext).crack()])


		#================= H@ndy T@b R3g!0n ================
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
		Password_info.setReadOnly(True)
		get_strength = QtWidgets.QPushButton("Get passsword strength")
		get_strength.clicked.connect(
			lambda:[get_pwd_strength(self.pwd_entry.text(), Password_info)])
		labframeLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.TopToBottom)
		info_label_frame.setLayout(labframeLayout)
		labframeLayout.addWidget(Password_info)
		labframeLayout.addWidget(get_strength)

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
		self.slct_num.setMinimum(1)
		slct_numGrpLayout = QtWidgets.QGridLayout()
		slct_numGrp.setLayout(slct_numGrpLayout)
		slct_numGrpLayout.addWidget(self.slct_num)

		NoBaseGrp = QtWidgets.QGroupBox()
		base_label1 = QtWidgets.QLabel("Selected Number Base:")
		self.number_base = QtWidgets.QSpinBox()
		self.number_base.setMinimum(1)
		self.number_base.setMaximum(140)
		_border_ = QtWidgets.QLabel("--"*25)

		NoBaseGrpLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		NoBaseGrp.setLayout(NoBaseGrpLayout)
		NoBaseGrpLayout.addWidget(base_label1)
		NoBaseGrpLayout.addWidget(self.number_base)

		ConvertBaseGrp = QtWidgets.QGroupBox()
		base_label2 = QtWidgets.QLabel("Convert To Base:")
		self.convert_base = QtWidgets.QSpinBox()
		self.convert_base.setMinimum(1)
		self.convert_base.setMaximum(140)
		ConvertBaseLayout = QtWidgets.QBoxLayout(QtWidgets.QBoxLayout.LeftToRight)
		ConvertBaseGrp.setLayout(ConvertBaseLayout)
		ConvertBaseLayout.addWidget(base_label2)
		ConvertBaseLayout.addWidget(self.convert_base)

		output_label_frame = QtWidgets.QGroupBox()
		output_label_frame.setTitle("Base Output")
		BaseOutput = QtWidgets.QTextEdit()
		BaseOutput.setReadOnly(True)
		BtnGrp = QtWidgets.QGroupBox()
		convert_btn = QtWidgets.QPushButton("Convert")
		convert_btn.clicked.connect(lambda :[cvrt(self.slct_num.value(),
			self.number_base.value(), self.convert_base.value(), BaseOutput)])
		copy_btn1 = QtWidgets.QPushButton("Copy")
		# -todo- Edit here when you know how to copy text from PyQt5 TextEdit widget
		copy_btn1.clicked.connect(lambda :[self.Copy2Clipboard(BaseOutput.toPlainText())])
		copy_btn1.clicked.connect(BaseOutput.copy)
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
		try:
			k1, k2 = int(self.key1.text()), int(self.key2.text())
		except ValueError:
			k1, k2 = None, None
		self.output.setText(eval(dct[self.selected_cipher.text()])(k1, data))

	def adjustWidget(self):
		if self.method.currentText()!=("Brute-force" or "Advanced brute-force"):
			self.wrd_alphs.setDisabled(True)
		else:
			self.wrd_alphs.setDisabled(False)

	def Copy2Clipboard(self, text):
		cb = QtWidgets.QApplication.clipboard()
		cb.clear(mode=cb.Clipboard)
		cb.setText(text, mode=cb.Clipboard)

	def folderLock(self, password, chosenDir, Option):
		import pyLocker, os
		from tkinter.messagebox import showerror, showinfo
		options = ['l', 'u', 'c', 'f']
		opted = Option
		if not opted.lower() in options:
			showerror("An Error Occured","Invalid Option, Try Again...")
		else:
			if not os.path.isdir(chosenDir):
				if not os.path.isdir(pyLocker.hideFileDirName):
					os.mkdir(chosenDir)

			if opted.lower() == 'u':
				if os.path.isdir(chosenDir):
					showinfo("Error","Folder is Already Unlocked, Press any key to exit...")
				else:
					pyLocker.unlock(password, chosenDir)

			elif opted.lower() == 'l':
				# pyLocker.call(["attrib", "-H", "-S", pyLocker.hideFileDirName])
				# os.remove(pyLocker.hideFileDirName)
				# if os.path.isdir(pyLocker.hideFileDirName):
				# if os.path.isdir(chosenDir):
				if os.path.isdir(pyLocker.hiddenFiles):
					pyLocker.showinfo("Error","Folder is Already Locked, Press any key to exit...")
				else:
					pyLocker.lock(chosenDir)

			elif opted.lower() == 'c':
				pyLocker.changePassword()

			elif opted.lower() == 'f':
				pyLocker.forgotPassword()

if __name__=='__main__':
	# if not admin.isUserAdmin():
	# admin.runAsAdmin()
	app = QtWidgets.QApplication(sys.argv)
	clipboard = app.clipboard()
	win = Window()
	win.show()
	sys.exit(app.exec_())



