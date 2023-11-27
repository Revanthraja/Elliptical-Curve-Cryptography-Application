import hashlib
import base64
import os
import sys
from Crypto.Cipher import AES
from hashlib import md5
from PyQt5 import QtGui, QtCore,QtWidgets
import collections
from eclib import EC
from eclib import DiffieHellman


class MainWindow(QtWidgets.QWidget):

    def __init__(self):
        QtWidgets.QWidget.__init__(self)
        global to_enc
        global dec1
        global dec2
        global label_ans
        self.data = ""

        self.setGeometry(0, 0, 500, 650)
        self.setWindowTitle("Elliptic Curve Cryptography")
        self.setWindowIcon(QtGui.QIcon("icon.png"))
        self.resize(500, 650)
        self.setMinimumSize(500, 650)
        self.center()
        self.tab_widget = QtWidgets.QTabWidget()
        tab = QtWidgets.QWidget()
        tab2 = QtWidgets.QWidget()
        p3_vertical = QtWidgets.QVBoxLayout(tab)


        self.tab_widget.addTab(tab, "EC Diffie Hellman")

        # ECDH GUI DECLARATIONS
        labele1 = QtWidgets.QLabel(" Elliptical Curve EQUATION ")
        labele2 = QtWidgets.QLabel("y^3 = x^2 + ax + b( mod q )")
        labele1.setStyleSheet('font-size: 13pt')
        labele2.setStyleSheet('font-size: 12pt')
        labele1.setAlignment(QtCore.Qt.AlignCenter)
        labele2.setAlignment(QtCore.Qt.AlignCenter)
        labela = QtWidgets.QLabel("Enter value of a:")
        labelb = QtWidgets.QLabel("Enter value of b:")
        labelc = QtWidgets.QLabel("Enter value of q (prime):")
        label_PrivA = QtWidgets.QLabel("Enter Private Key of A:")
        label_PrivB = QtWidgets.QLabel("Enter Private Key of B:")
        label_result = QtWidgets.QLabel("ENCODED / DECODED TEXT")
        label_result.setStyleSheet('font-size: 12pt')
        textEdit = QtWidgets.QTextEdit()
        button_file = QtWidgets.QPushButton("Import File")
        button_encrypt = QtWidgets.QPushButton("Encrypt")
        button_decrypt = QtWidgets.QPushButton("Decrypt")
        button_file.clicked.connect(self.importfile)
        button_encrypt.clicked.connect(self.ecdhencrypt)
        button_decrypt.clicked.connect(self.ecdhdecrypt)
        self.vala = QtWidgets.QTextEdit()
        self.valb = QtWidgets.QTextEdit()
        self.valc = QtWidgets.QTextEdit()
        self.apriv = QtWidgets.QTextEdit()
        self.bpriv = QtWidgets.QTextEdit()
        self.textEdit = QtWidgets.QTextEdit()
        self.vala.setMaximumHeight(int(labela.sizeHint().height() * 1.5))

        self.valb.setMaximumHeight(int(labelb.sizeHint().height() * 1.5))

        self.valc.setMaximumHeight(int(labelc.sizeHint().height() * 1.5))

        self.apriv.setMaximumHeight(int(label_PrivA.sizeHint().height() * 1.5))

        self.bpriv.setMaximumHeight(int(label_PrivB.sizeHint().height() * 1.5))

        hbox = QtWidgets.QHBoxLayout()
        hbox1 = QtWidgets.QHBoxLayout()
        vbox1 = QtWidgets.QHBoxLayout()
        vbox2 = QtWidgets.QHBoxLayout()

        # GUI LAYOUT
        p3_vertical.addWidget(labele1)
        p3_vertical.addWidget(labele2)
        vbox1.addWidget(labela)
        vbox1.addWidget(self.vala)
        vbox2.addWidget(labelb)
        vbox2.addWidget(self.valb)
        hbox1.addLayout(vbox1)
        hbox1.addLayout(vbox2)
        p3_vertical.addLayout(hbox1)
        p3_vertical.addWidget(labelc)
        p3_vertical.addWidget(self.valc)
        p3_vertical.addWidget(label_PrivA)
        p3_vertical.addWidget(self.apriv)
        p3_vertical.addWidget(label_PrivB)
        p3_vertical.addWidget(self.bpriv)
        p3_vertical.addWidget(button_file)
        p3_vertical.addWidget(label_result)
        p3_vertical.addWidget(self.textEdit)
        hbox.addWidget(button_encrypt)
        hbox.addWidget(button_decrypt)
        p3_vertical.addStretch(1)
        p3_vertical.addLayout(hbox)

        vbox = QtWidgets.QVBoxLayout()
        vbox.addWidget(self.tab_widget)
        self.setLayout(vbox)

    # GUI Functionality
    def ecdhencrypt(self):
        global A, B, C, PrivA, PrivB
        txt = self.data 
        A = int(self.vala.toPlainText())
        B = int(self.valb.toPlainText())
        C = int(self.valc.toPlainText())
        PrivA = int(self.apriv.toPlainText())
        PrivB = int(self.bpriv.toPlainText())
        ec = EC(A, B, C)
        g, _ = ec.at(7)
        assert ec.order(g) <= ec.q
        dh = DiffieHellman(ec, g)
        apub = dh.gen(PrivA)
        bpub = dh.gen(PrivB)
        assert dh.secret(PrivA, bpub) == dh.secret(PrivB, apub)
        
        BLOCK_SIZE = 64
        PADDING = '{'

        def pad(s):
            if isinstance(s, str):
                s = s.encode('utf-8')  # Convert string to bytes if it's a string
            return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING.encode('utf-8')  # Encode PADDING as bytes

        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

        x, y = dh.secret(PrivA, apub)
        shared_secret = x + y
        secret = hashlib.md5(str(shared_secret).encode()).digest()
        cipher = AES.new(secret, AES.MODE_ECB)
        encoded = EncodeAES(cipher, txt.encode('utf-8'))

        with open('Encrypted.txt', 'wb') as file:
            file.write(encoded)

        self.textEdit.setText(encoded.decode('utf-8'))
    def ecdhdecrypt(self):
        global A, B, C, PrivA, PrivB
        A = int(self.vala.toPlainText())
        B = int(self.valb.toPlainText())
        C = int(self.valc.toPlainText())
        PrivA = int(self.apriv.toPlainText())
        PrivB = int(self.bpriv.toPlainText())
        txt = self.data

        ec = EC(A, B, C)
        g, _ = ec.at(7)
        assert ec.order(g) <= ec.q
        dh = DiffieHellman(ec, g)
        apub = dh.gen(PrivA)
        bpub = dh.gen(PrivB)
        assert dh.secret(PrivA, bpub) == dh.secret(PrivB, apub)

        BLOCK_SIZE = 64
        PADDING = '{'

        def pad(s):
            if isinstance(s, str):
                s = s.encode('utf-8')  # Convert string to bytes if it's a string
            return s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING.encode('utf-8')  # Encode PADDING as bytes

        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING.encode('utf-8'))

        x, y = dh.secret(PrivA, apub)
        shared_secret = x + y
        secret = hashlib.md5(str(shared_secret).encode()).digest()
        cipher = AES.new(secret, AES.MODE_ECB)
        decoded = DecodeAES(cipher, txt.encode('utf-8'))

        with open('Decrypted.txt', 'wb') as file:
            file.write(decoded)

        self.textEdit.setText(decoded.decode('utf-8'))



    def importfile(self):
        global data
        fname, _ = QtWidgets.QFileDialog.getOpenFileName(self, 'Open file', '/home')
        with open(fname, 'r') as file:
                self.data = file.read()  # Assign content to 'data' variable


    def center(self):
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move(int((screen.width() - size.width()) / 2), int((screen.height() - size.height()) / 2))


    def loadValues(self):
        global ec
        global eg
        idx = self.tab_widget.currentIndex()
        if idx == 1:
            global g
            global pub
            ec = EC(a, b, q)
            g, _ = ec.at(7)
            eg = ElGamal(ec, g)
            pub = eg.gen(priv)
            print_pub = str(pub[0]) + "," + str(pub[1])
            self.elg_key.insertPlainText(print_pub)

app = QtWidgets.QApplication(sys.argv)
frame = MainWindow()
frame.show()
sys.exit(app.exec_())
