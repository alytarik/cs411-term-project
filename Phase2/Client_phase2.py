{
 "cells": [
  {
   "cell_type": "code",
   "execution_count": 1,
   "metadata": {},
   "outputs": [],
   "source": [
    "import math\n",
    "import time\n",
    "import random\n",
    "import sympy\n",
    "import warnings\n",
    "from random import randint, seed\n",
    "import sys\n",
    "from ecpy.curves import Curve,Point\n",
    "from Crypto.Hash import SHA3_256, HMAC, SHA256\n",
    "import requests\n",
    "from Crypto.Cipher import AES\n",
    "from Crypto import Random\n",
    "from Crypto.Util.Padding import pad\n",
    "from Crypto.Util.Padding import unpad\n",
    "import random\n",
    "import re\n",
    "import json"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 2,
   "metadata": {},
   "outputs": [],
   "source": [
    "API_URL = 'http://10.92.52.255:5000/'\n",
    "\n",
    "stuID = 28374"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 3,
   "metadata": {},
   "outputs": [],
   "source": [
    "E = Curve.get_curve('secp256k1')\n",
    "n = E.order\n",
    "p = E.field\n",
    "P = E.generator\n",
    "a = E.a\n",
    "b = E.b"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 4,
   "metadata": {},
   "outputs": [],
   "source": [
    "def egcd(a, b):\n",
    "    x,y, u,v = 0,1, 1,0\n",
    "    while a != 0:\n",
    "        q, r = b//a, b%a\n",
    "        m, n = x-u*q, y-v*q\n",
    "        b,a, x,y, u,v = a,r, u,v, m,n\n",
    "    gcd = b\n",
    "    return gcd, x, y\n",
    "\n",
    "def modinv(a, m):\n",
    "    gcd, x, y = egcd(a, m)\n",
    "    if gcd != 1:\n",
    "        return None  # modular inverse does not exist\n",
    "    else:\n",
    "        return x % m\n",
    "\n",
    "def Setup():\n",
    "    E = Curve.get_curve('secp256k1')\n",
    "    return E\n",
    "\n",
    "def KeyGen(E):\n",
    "    n = E.order\n",
    "    P = E.generator\n",
    "    sA = randint(1,n-1)\n",
    "    QA = sA*P\n",
    "    return sA, QA\n",
    "\n",
    "def SignGen(message, E, sA):\n",
    "    n = E.order\n",
    "    P = E.generator\n",
    "    k = randint(1, n-2)\n",
    "    R = k*P\n",
    "    r = R.x % n\n",
    "    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n\n",
    "    s = (sA*h + k) % n\n",
    "    return h, s\n",
    "\n",
    "def SignVer(message, h, s, E, QA):\n",
    "    n = E.order\n",
    "    P = E.generator\n",
    "    V = s*P - h*QA\n",
    "    v = V.x % n\n",
    "    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n\n",
    "    if h_ == h:\n",
    "        return True\n",
    "    else:\n",
    "        return False\n",
    "\n",
    "\n",
    "#server's Identitiy public key\n",
    "IKey_Ser = Point(93223115898197558905062012489877327981787036929201444813217704012422483432813 , 8985629203225767185464920094198364255740987346743912071843303975587695337619, E)\n",
    "\n",
    "def IKRegReq(h,s,x,y):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.put('{}/{}'.format(API_URL, \"IKRegReq\"), json = mes)\t\t\n",
    "    if((response.ok) == False): print(response.json())\n",
    "\n",
    "def IKRegVerify(code):\n",
    "    mes = {'ID':stuID, 'CODE': code}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.put('{}/{}'.format(API_URL, \"IKRegVerif\"), json = mes)\n",
    "    if((response.ok) == False): raise Exception(response.json())\n",
    "    print(response.json())\n",
    "\n",
    "def SPKReg(h,s,x,y):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.put('{}/{}'.format(API_URL, \"SPKReg\"), json = mes)\t\t\n",
    "    if((response.ok) == False): \n",
    "        print(response.json())\n",
    "    else: \n",
    "        res = response.json()\n",
    "        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']\n",
    "\n",
    "def OTKReg(keyID,x,y,hmac):\n",
    "    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.put('{}/{}'.format(API_URL, \"OTKReg\"), json = mes)\t\t\n",
    "    print(response.json())\n",
    "    if((response.ok) == False): return False\n",
    "    else: return True\n",
    "\n",
    "\n",
    "def ResetIK(rcode):\n",
    "    mes = {'ID':stuID, 'RCODE': rcode}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.delete('{}/{}'.format(API_URL, \"ResetIK\"), json = mes)\t\t\n",
    "    print(response.json())\n",
    "    if((response.ok) == False): return False\n",
    "    else: return True\n",
    "\n",
    "def ResetSPK(h,s):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.delete('{}/{}'.format(API_URL, \"ResetSPK\"), json = mes)\t\t\n",
    "    print(response.json())\n",
    "    if((response.ok) == False): return False\n",
    "    else: return True\n",
    "\n",
    "def ResetOTK(h,s):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.delete('{}/{}'.format(API_URL, \"ResetOTK\"), json = mes)\t\t\n",
    "    print(response.json())\n",
    "\n",
    "############## The new functions of phase 2 ###############\n",
    "\n",
    "#Pseudo-client will send you 5 messages to your inbox via server when you call this function\n",
    "def PseudoSendMsg(h,s):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.put('{}/{}'.format(API_URL, \"PseudoSendMsg\"), json = mes)\t\t\n",
    "    print(response.json())\n",
    "\n",
    "#Get your messages. server will send 1 message from your inbox\n",
    "def ReqMsg(h,s):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.get('{}/{}'.format(API_URL, \"ReqMsg\"), json = mes)\t\n",
    "    print(response.json())\t\n",
    "    if((response.ok) == True): \n",
    "        res = response.json()\n",
    "        return res[\"IDB\"], res[\"OTKID\"], res[\"MSGID\"], res[\"MSG\"], res[\"EK.X\"], res[\"EK.Y\"]\n",
    "\n",
    "#Get the list of the deleted messages' ids.\n",
    "def ReqDelMsg(h,s):\n",
    "    mes = {'ID':stuID, 'H': h, 'S': s}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.get('{}/{}'.format(API_URL, \"ReqDelMsgs\"), json = mes)      \n",
    "    print(response.json())      \n",
    "    if((response.ok) == True): \n",
    "        res = response.json()\n",
    "        return res[\"MSGID\"]\n",
    "\n",
    "#If you decrypted the message, send back the plaintext for checking\n",
    "def Checker(stuID, stuIDB, msgID, decmsg):\n",
    "    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}\n",
    "    print(\"Sending message is: \", mes)\n",
    "    response = requests.put('{}/{}'.format(API_URL, \"Checker\"), json = mes)\t\t\n",
    "    print(response.json())\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 21,
   "metadata": {},
   "outputs": [],
   "source": [
    "def GenerateKey(pri=-1):\n",
    "  if pri == -1:\n",
    "    pri = random.randint(0,n-1)\n",
    "  pub = pri * P\n",
    "  return pri, pub"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 14,
   "metadata": {},
   "outputs": [],
   "source": [
    "IKey_Pr = int.from_bytes(b\"this is a very very very secret key!\", byteorder=\"big\") % n\n",
    "IKey_Pub = IKey_Pr * P"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 15,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "14660324670243075630000635893444662718789579794562255004660387285071415640046"
      ]
     },
     "execution_count": 15,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "IKey_Pr"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 16,
   "metadata": {},
   "outputs": [
    {
     "data": {
      "text/plain": [
       "True"
      ]
     },
     "execution_count": 16,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "stuID_signed = SignGen(stuID.to_bytes(math.ceil(stuID.bit_length()/8), \"big\"), E, IKey_Pr)\n",
    "SignVer(stuID.to_bytes(math.ceil(stuID.bit_length()/8),\"big\"), stuID_signed[0], stuID_signed[1], E, IKey_Pub)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 17,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790, 'IKPUB.X': 59789841742109204850564918020815376627555014601137729807885099765009802042661, 'IKPUB.Y': 57547776729331717451156309143069826691328908716635831074670254759332423229699}\n"
     ]
    }
   ],
   "source": [
    "IKRegReq(stuID_signed[0], stuID_signed[1], IKey_Pub.x,  IKey_Pub.y)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 18,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'CODE': 755431}\n",
      "Registered successfully\n"
     ]
    }
   ],
   "source": [
    "CODE = 755431\n",
    "IKRegVerify(CODE)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 19,
   "metadata": {},
   "outputs": [],
   "source": [
    "RCODE = 633211"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 25,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "11786423727943086685271019354073903964054819384868285139085017019872442465785\n"
     ]
    }
   ],
   "source": [
    "SPK_A_Pri, SPK_A_Pub = GenerateKey(11786423727943086685271019354073903964054819384868285139085017019872442465785)\n",
    "print(SPK_A_Pri)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 26,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'H': 108348270822108090422994039472485554343924153630867983777076272522898898572918, 'S': 10048727423621387549837008796301057918749209776632786805594323474920692603181, 'SPKPUB.X': 31229216498439133952347392112572115637714405472383255423741905893245939825627, 'SPKPUB.Y': 15829632064927002234237681052859941715925515902168887028034362059443643752689}\n"
     ]
    }
   ],
   "source": [
    "SPK_A_message = SPK_A_Pub.x.to_bytes(math.ceil(SPK_A_Pub.x.bit_length()/8), 'big') + SPK_A_Pub.y.to_bytes(math.ceil(SPK_A_Pub.y.bit_length()/8), 'big')\n",
    "SPK_A_h, SPK_A_s = SignGen(SPK_A_message, E, IKey_Pr)\n",
    "SPK_S_X, SPK_S_Y, SPK_S_h, SPK_S_s = SPKReg(SPK_A_h, SPK_A_s, SPK_A_Pub.x, SPK_A_Pub.y)\n",
    "SPK_S_Pub = Point(SPK_S_X, SPK_S_Y, E)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 126,
   "metadata": {},
   "outputs": [],
   "source": [
    "# Generate HMAX Key\n",
    "T = SPK_A_Pri * SPK_S_Pub\n",
    "U = b'CuriosityIsTheHMACKeyToCreativity' + T.y.to_bytes(math.ceil(T.y.bit_length()/8), 'big') + T.x.to_bytes(math.ceil(T.x.bit_length()/8), 'big')\n",
    "K_HMAC = SHA3_256.new(U).digest()"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 127,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "All OTKs deleted !\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 0, 'OTKI.X': 115685243949069798117800815280834184372725585328651245467488322216030752273591, 'OTKI.Y': 4041286537204748928238020567131343755689969080138053507371479663532179284781, 'HMACI': 'f2c91bbaf0985514a93c8b5cdab46e6609b25d98e8f9f180fe54393b06e98e55'}\n",
      "OTK with ID number 0 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 1, 'OTKI.X': 43486192186188829341694497876383026332163303519242520562405506995611050704267, 'OTKI.Y': 103736672655958991909355251913895026756204118951460619651534377827552584472808, 'HMACI': '2db585fdb81c590cca49e58691e71c4f2d00935dada72d3100cd465db3592d3c'}\n",
      "OTK with ID number 1 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 2, 'OTKI.X': 27056136591144707149628783235382323029513406130838368635084326251902050645927, 'OTKI.Y': 54229741758555987856984605785715909570176436425847847233071732078235633294696, 'HMACI': 'b949f13ff88e782315178f682a3a021631a5b5624df6eeeb17d81bafed94f7c2'}\n",
      "OTK with ID number 2 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 3, 'OTKI.X': 89671972177120298671058814992739086010077189553785566506853948242293090344825, 'OTKI.Y': 26959271399663310174533244568173783892628701158859699445816088332842563166127, 'HMACI': '6b0772cf259fdbfac9f9c589b130a08a3e167fef845b48fa4c9232a6460e3bea'}\n",
      "OTK with ID number 3 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 4, 'OTKI.X': 102224868246649808930901684780054207167068624377091954987905223247479060553313, 'OTKI.Y': 32564308668966365177046941191344054006594250642770546021641605788378244070403, 'HMACI': 'a2b07ce13c9d03660bb669a184ecc3d20797796227019e1f83ccef8c69060a83'}\n",
      "OTK with ID number 4 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 5, 'OTKI.X': 109292593279762655189041710221680530080785095229026084638179985916309926254321, 'OTKI.Y': 40897383494842037421364065976445004430321663185815958631153534829631695032453, 'HMACI': '6e43520d15fc562c3b5bae1b306193f1f3d8eaa1c6678d235c788afb3a0565e6'}\n",
      "OTK with ID number 5 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 6, 'OTKI.X': 43069900082075144143157064249523612255916493518427061976149382685654793174319, 'OTKI.Y': 84588824190963866098571966990255676775336831898292227365986723211687504707640, 'HMACI': '6bd371a6778b2fa8b95261c1621a4cd466db68884679a2fa2225639734f40f91'}\n",
      "OTK with ID number 6 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 7, 'OTKI.X': 31612936939223585978333794347416825098962970187074024195105538188710473954824, 'OTKI.Y': 55837248228311492822208785158069536656630337257337030248830916037569164484440, 'HMACI': 'b96d8056145aee04d49241813beff3ff062e77041ee2c30707e29ca5701db053'}\n",
      "OTK with ID number 7 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 8, 'OTKI.X': 86835573088189417948137562021547233254524491804188479467474399443019977931207, 'OTKI.Y': 40588688731323724574523494611534142217167738564540192722372126696910213058856, 'HMACI': 'ea76929fecbdabc786ca7565f6b46e964f6aabff843f4f3dd56710639246b24a'}\n",
      "OTK with ID number 8 is registered successfully\n",
      "Sending message is:  {'ID': 28374, 'KEYID': 9, 'OTKI.X': 7913777307025415372712014639843961553486783623680029280144184197665641391608, 'OTKI.Y': 73895497985126029035802638504916319051200501522647869108251580403981322389556, 'HMACI': 'de3c55763e3fea6c0cb675271a76c0e27530c1474048fbc661bb4e7b6ca9dbea'}\n",
      "OTK with ID number 9 is registered successfully\n"
     ]
    }
   ],
   "source": [
    "# Generate OTKs\n",
    "ResetOTK(stuID_signed[0], stuID_signed[1])\n",
    "OTKs=[]\n",
    "for i in range(10):\n",
    "  priv, pub = GenerateKey()\n",
    "  m = pub.x.to_bytes(math.ceil(pub.x.bit_length()/8), 'big') + pub.y.to_bytes(math.ceil(pub.y.bit_length()/8), 'big')\n",
    "  hmaci = HMAC.new(K_HMAC, m, digestmod=SHA256).hexdigest()\n",
    "  OTKReg(i, pub.x, pub.y, hmaci)\n",
    "  OTKs.append(priv)"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 155,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "Your favourite pseudo-client sent you 5 messages. You can get them from the server\n"
     ]
    }
   ],
   "source": [
    "PseudoSendMsg(stuID_signed[0], stuID_signed[1])"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 156,
   "metadata": {},
   "outputs": [],
   "source": [
    "def GetSessionKey(OTK, EK):\n",
    "  T = OTK * EK\n",
    "  U = T.x.to_bytes(math.ceil(T.x.bit_length()/8), \"big\") + T.y.to_bytes(math.ceil(T.y.bit_length()/8), \"big\") + b'ToBeOrNotToBe'\n",
    "  KS = SHA3_256.new(U).digest()\n",
    "  return KS"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 157,
   "metadata": {},
   "outputs": [],
   "source": [
    "def GetKDF(K_KDF):\n",
    "  K_ENC = SHA3_256.new(K_KDF + b'YouTalkingToMe').digest()\n",
    "  K_HMAC = SHA3_256.new(K_KDF + K_ENC + b'YouCannotHandleTheTruth').digest()\n",
    "  K_KDF_N = SHA3_256.new(K_ENC + K_HMAC + b'MayTheForceBeWithYou').digest()\n",
    "  return K_ENC, K_HMAC, K_KDF_N"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 158,
   "metadata": {},
   "outputs": [],
   "source": [
    "def VerifyHMAC(m, K_HMAC):\n",
    "  nonce = m[:8]\n",
    "  hmac = m[-32:]\n",
    "  msg = m[8:-32]\n",
    "\n",
    "  hmac_new = HMAC.new(K_HMAC, msg,digestmod=SHA256)\n",
    "  hmac_final = hmac_new.digest()\n",
    "\n",
    "  if(hmac == hmac_final):\n",
    "    return m[:-32]\n",
    "  return \"INVALIDHMAC\""
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 159,
   "metadata": {},
   "outputs": [],
   "source": [
    "def AesDecrypt(ctext, key):\n",
    "  cipher = AES.new(key, AES.MODE_CTR, nonce=ctext[:8])\n",
    "  ptext = cipher.decrypt(ctext[8:])\n",
    "  ptext = ptext.decode('UTF-8')\n",
    "  print(\"plaintext:\", ptext)\n",
    "  return ptext"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 160,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "{'IDB': 18007, 'OTKID': 4, 'MSGID': 1, 'MSG': 62803458082930893607224899765222113941787897389755230745192023906944194330316437431013510562287420652368792814048508750658801626713074059961983080001522641595589950839102708521547375037195280044420656, 'EK.X': 15368298955619207350785244334660552457799259606964971405554819582548341564227, 'EK.Y': 11348335272776435107750455452900771899285409725348386597504350605206590801175}\n",
      "plaintext: https://www.youtube.com/watch?v=mJXUNMexT1c\n",
      "Sending message is:  {'IDA': 28374, 'IDB': 18007, 'MSGID': 1, 'DECMSG': 'https://www.youtube.com/watch?v=mJXUNMexT1c'}\n",
      "You decrypted it correctly, wow!\n",
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "{'IDB': 18007, 'OTKID': 4, 'MSGID': 2, 'MSG': 75411334641340437465973809999241440772680972674709418323536168214979818054038031115373102753390810926573798301940370719136532986636815038274036784993000133912581616074998688061475858941021109554356245, 'EK.X': 15368298955619207350785244334660552457799259606964971405554819582548341564227, 'EK.Y': 11348335272776435107750455452900771899285409725348386597504350605206590801175}\n",
      "plaintext: https://www.youtube.com/watch?v=mJXUNMexT1c\n",
      "Sending message is:  {'IDA': 28374, 'IDB': 18007, 'MSGID': 2, 'DECMSG': 'https://www.youtube.com/watch?v=mJXUNMexT1c'}\n",
      "You decrypted it correctly, wow!\n",
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "{'IDB': 18007, 'OTKID': 4, 'MSGID': 3, 'MSG': 7867155744760219117694960827706408445116251403924153583643164770858399777445657819257268708748842655213865125991678245993593426623280540773375992015667843076278271376755307776437455114549619569791509, 'EK.X': 15368298955619207350785244334660552457799259606964971405554819582548341564227, 'EK.Y': 11348335272776435107750455452900771899285409725348386597504350605206590801175}\n",
      "plaintext: https://www.youtube.com/watch?v=379oevm2fho\n",
      "Sending message is:  {'IDA': 28374, 'IDB': 18007, 'MSGID': 3, 'DECMSG': 'https://www.youtube.com/watch?v=379oevm2fho'}\n",
      "You decrypted it correctly, wow!\n",
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "{'IDB': 18007, 'OTKID': 4, 'MSGID': 4, 'MSG': 46885358133191286974320246769092094834166120104383407204665718284490310391176450553740260706543875626412756414812810544909324494095007953407529365230821085783446239496537420292970847608056914570360629, 'EK.X': 15368298955619207350785244334660552457799259606964971405554819582548341564227, 'EK.Y': 11348335272776435107750455452900771899285409725348386597504350605206590801175}\n",
      "plaintext: https://www.youtube.com/watch?v=s3Nr-FoA9Ps\n",
      "Sending message is:  {'IDA': 28374, 'IDB': 18007, 'MSGID': 4, 'DECMSG': 'https://www.youtube.com/watch?v=s3Nr-FoA9Ps'}\n",
      "You decrypted it correctly, wow!\n",
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "{'IDB': 18007, 'OTKID': 4, 'MSGID': 5, 'MSG': 34041135396570594764933342840841951145694675255214383856332632484830096119320450387712835009165137381051389509387681088327320631023028470586256091717220040690960000681976952721790069731096397076216782, 'EK.X': 15368298955619207350785244334660552457799259606964971405554819582548341564227, 'EK.Y': 11348335272776435107750455452900771899285409725348386597504350605206590801175}\n",
      "Invalid\n",
      "Sending message is:  {'IDA': 28374, 'IDB': 18007, 'MSGID': 5, 'DECMSG': 'INVALIDHMAC'}\n",
      "You've found the faulty message. Good job!\n"
     ]
    }
   ],
   "source": [
    "for i in range(5):\n",
    "  stuIDB, otkID, msgID, msg, EK_X, EK_Y = ReqMsg(stuID_signed[0], stuID_signed[1])\n",
    "  KS = GetSessionKey(OTKs[otkID], Point(EK_X, EK_Y, E))\n",
    "  if i == 0:\n",
    "    K_ENC, K_HMAC, K_KDF_N = GetKDF(KS)\n",
    "  else:\n",
    "    K_ENC, K_HMAC, K_KDF_N = GetKDF(K_KDF_N)\n",
    "\n",
    "  msg = VerifyHMAC(msg.to_bytes(math.ceil(msg.bit_length()/8),\"big\"), K_HMAC)\n",
    "  \n",
    "  if(msg!=\"INVALIDHMAC\"):\n",
    "    plaintext = AesDecrypt(msg, K_ENC)\n",
    "    Checker(stuID, stuIDB, msgID, plaintext)\n",
    "  else:\n",
    "    print(\"Invalid\")\n",
    "    Checker(stuID, stuIDB, msgID, \"INVALIDHMAC\")\n",
    "\n"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": 161,
   "metadata": {},
   "outputs": [
    {
     "name": "stdout",
     "output_type": "stream",
     "text": [
      "Sending message is:  {'ID': 28374, 'H': 87296569060803083444075585464439704525150279672138137976537215103596054115583, 'S': 49730945680804712394027219327989636888361784100593711215124587938945737868790}\n",
      "{'MSGID': [1, 2, 4, 5]}\n"
     ]
    },
    {
     "data": {
      "text/plain": [
       "[1, 2, 4, 5]"
      ]
     },
     "execution_count": 161,
     "metadata": {},
     "output_type": "execute_result"
    }
   ],
   "source": [
    "ReqDelMsg(stuID_signed[0],stuID_signed[1])"
   ]
  },
  {
   "cell_type": "code",
   "execution_count": null,
   "metadata": {},
   "outputs": [],
   "source": []
  }
 ],
 "metadata": {
  "kernelspec": {
   "display_name": "Python 3",
   "language": "python",
   "name": "python3"
  },
  "language_info": {
   "codemirror_mode": {
    "name": "ipython",
    "version": 3
   },
   "file_extension": ".py",
   "mimetype": "text/x-python",
   "name": "python",
   "nbconvert_exporter": "python",
   "pygments_lexer": "ipython3",
   "version": "3.10.7"
  },
  "orig_nbformat": 4,
  "vscode": {
   "interpreter": {
    "hash": "f5fe054353a3ea95c740dbd5d0157a46c65128dd73b0bf0efea202159c214138"
   }
  }
 },
 "nbformat": 4,
 "nbformat_minor": 2
}
