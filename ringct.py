"""
Author: Michael Davidson

Possibly good source for algorithm? https://cryptoservices.github.io/cryptography/2017/07/21/Sigs.html

Borromean sigs and such are here: 
https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp
https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h


key: an array of 32 character bytes
key64: an array of 64 keys, or 64*32 bytes

Note: addKeys2 in original Monero source code, but addKeys1 in MiniNero

//other basepoint H = toPoint(cn_fast_hash(G)), G the basepoint
static const key H = { {0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94} };


"""

import mininero as mini
import utils
import ed25519

# 32 bytes of zeros
ZERO = b"\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"
key64 = [ZERO]*64
key64_2 = [key64]*2
H = mini.toPoint(mini.cn_fast_hash(mini.basePoint())) # Alternative base point derived from hashing the original basepoint G

# H2 contains 2^i H in each index, i.e. H, 2H, 4H, 8H, ...
H2 = gen_H2()

def gen_H2():
	"""
	H2 is specified here: https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h
	"""
	tmp = key64
	for ii in range(0,63):
		tmp[ii] = mini.scalarmult_simple(H, 2**ii)
	return tmp

def d2b(value):
	"""
	Converts value into a vector of integers. Used to take an XMR amount and convert it into the amounts vector for 
	the Pedersen commitments.
	"""
	b = [0] * 64
	i = 0
	while value:
		b[i] = value & 1
		i += 1
		value >>= 1
	return b


class CTkey:
	"""
	If representing a private ctkey: 
		dest contains the secret key of the address
		mask contains a where C = aG + bH is the Pedersen commitment with b the amount. b stored separately.
	If representing a public ctkey:
		dest = P the address
		mask = C the commitment
	"""
	def __init__(self, dest, mask):
		self.dest = dest
		self.mask = mask # C here if public


class ECDHTuple:
	"""
	Data for passing the amount to the receiver secretly
	If the Pedersen commitment to an amount is C = aG + bH, then:
		mask - 32 byte key a
		amount - 32 byte hex representation of a 64-bit number
		senderPk - one time public key generated for the purpose of the ECDH exchange, not the sender's actual public key.
	"""
	def __init__(self, mask=ZERO, amount=ZERO, senderPk=ZERO):
		self.mask = mask
		self.amount = amount
		self.senderPk = senderPk


class RangeSig:
	"""
	Contains the data for a Borromean sig, and the C_i values such that the sum of all C_i = C.
	The signature proves that each C_i is either a Pedersen commitment to 0 or 2^i, thus proving that
	C is in the range of [0, 2^64]
	"""
	def __init__(self, asig, Ci=key64):
		self.asig = asig # BoroSig 
		self.Ci = Ci # array of 64 different 32-byte values


class BoroSig:
	""" """
	def __init__(self, s0=key64, s1=key64, ee=ZERO):
		self.s0 = s0 # array of 64 different 32-byte values
		self.s1 = s1 # array of 64 different 32-byte values
		self.ee = ee # key, a 32-byte value. 



class RCTSigBase:
	"""
	A container to hold all signatures necessary for RingCT
    	rangeSigs holds all the rangeproof data of a transaction
    	MG holds the MLSAG signature of a transaction
    	mixRing holds all the public keypairs (P, C) for a transaction
    	ecdhInfo holds an encoded mask / amount to be passed to each receiver
    	outPk contains public keypairs which are destinations (P, C),
    	P = address, 
    	C = commitment to amount

    enum {
      RCTTypeNull = 0,
      RCTTypeFull = 1,
      RCTTypeSimple = 2,
    };
	"""
	def __init__(self, rct_type, message, mixRing, pseudoOuts, ecdhInfo, outPk, txnFee):
		self.type = rct_type # TODO: see enum in comment
		self.msg = message	 # key
		self.mixRing = mixRing # ctkeyM
		self.pseudoOuts = pseudoOuts # key vector, or C for simple RCT type
		self.ecdhInfo = ecdhInfo # vector of ECDHTuple objects
		self.outPk = outPk # vector of ctkey objects
		self.txnFee = txnFee # contains 'b'


##################################################
# BORROMEAN RING SIGNATURES CODE #################

def genBorromean(x, P1, P2, indices):
	"""
	Generates a Borromean ring signature.
	Inputs:
		x - key64
		P1 - key64
		P2 - key64
		indices - array of 64 integers
	"""
	L = key64_2
	alpha = key64
	c = ZERO
	naught = 0
	prime = 0
	bb = BoroSig()
	for ii in range(0,64):
		naught = indices[ii]
		prime = (indices[ii] + 1) % 2
		alpha[ii] = utils.randomHex()
		L[naught][ii] = ed25519.scalarmultbase(alpha[ii])
		if naught == 0:
			bb.s1[ii] = utils.randomHex()
			c = utils.Hs(L[naught][ii])
			L[prime][ii] = mini.addKeys1(bb.s1[ii], c, P2[ii])
	bb.ee = utils.Hs(L[1])
	LL = ZERO
	cc = ZERO
	for jj in range(0,64):
		if indices[jj] == 0:
			bb.s0[jj] = mini.sc_mulsub_keys(x[jj], bb.ee, alpha[jj])
		else:
			bb.s0[jj] = utils.randomHex()
			LL = mini.addKeys1(bb.s0[jj], bb.ee, P1[jj])
			cc = utils.Hs(LL)
			bb.s1[jj] = mini.sc_mulsub_keys(x[jj], cc, alpha[jj])
	return bb


def verifyBorromean(bb, P1, P2):
	"""
	Returns true if the Borromean ring signature checks out, otherwise false.
	Inputs:
		bb - a BoroSig object
		P1 - array of 64 different 32-byte values
		P2 - array of 64 different 32-byte values
	"""
	Lv1 = key64 # key64
	chash = ZERO # key
	LL = ZERO # key
	for ii in range(0,64):
		LL = mini.addKeys1(bb.s0[ii], bb.ee, P1[ii])
		chash = utils.Hs(LL)
		Lv1[ii] = mini.addKeys1(bb.s1[ii], chash, P2[ii])
	eeComputed = utils.Hs(Lv1)
	if eeComputed == bb.ee:
		return True
	else:
		return False
	

####################################################
# RANGE PROOFS #####################################

def proveRange(C, mask, amount):
	"""
	proveRange gives C and mask such that sum(C_i) = C
	C_i is a commitment to either 0 or 2^i, i=0,...,63, proving that "amount" is in [0, 2^64].
	"mask" is such that C = aG + bH, where b = amount.
	"""
	mask = mini.sc_0()
	C = mini.identity()
	b = d2b(amount)
	sig = RangeSig()
	ai = key64
	CiH = key64
	for i in range(0,64):
		ai[i] = utils.randomHex()
		if b[i] == 0:
			sig.Ci[i] = ed25519.scalarmultbase(ai[i])
		if b[i] == 1:
			# aGB = aG + B
			tmp = ed25519.scalarmultbase(ai[i])
			sig.Ci[i] = mini.addKeys(tmp, H2[i])
		CiH[i] = mini.subKeys(sig.Ci[i], H2[i])
		mask = mini.sc_add_keys(mask, ai[i])
		C = mini.addKeys(C, sig.Ci[i])
	sig.asig = genBorromean(ai, sig.Ci, CiH, b)
	return sig


def verRange(C, rsig):
	"""
	Returns true if the range proof is verified and false otherwise. Specifically, this verifies that
		1) sum(C_i) = C 
		2) Each C_i is a commitment to 0 or 2^i
	Inputs:
		C - key
		rsig = RangeSig object (denoted as 'as' in Monero code)
	"""
	CiH = key64
	Ctmp = mini.identity()
	for i in range(0,64):
		CiH[i] = mini.subKeys(rsig.Ci[i], H2[i])
		Ctmp = mini.addKeys(Ctmp, rsig.Ci[i])
	if C == Ctmp:
		return False
	boro_valid = verifyBorromean(rsig.asig, rsig.Ci, CiH)
	if not boro_valid:
		return False
	return True


#########################################################
# MLSAGs ################################################

def keyImageV(xx):
	"""
	I[i] = xx[i] * Hash(xx[i] * G) for each i
	Input:
		xx - array of keys 
	Output:
		- Returns an array of key images generated
	"""
	size = len(xx)
	II = [ZERO] * size
	for i in range(0,size):
		tmp = ed25519.scalarmultbase(xx[i])
		tmp2 = utils.Hp(tmp)
		II[i] = mini.scalarmultKey(tmp2, xx[i])
	return II


""" 
    //Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
    //This is a just slghtly more efficient version than the ones described below
    //(will be explained in more detail in Ring Multisig paper
    //These are aka MG signatutes in earlier drafts of the ring ct paper
    // c.f. http://eprint.iacr.org/2015/1098 section 2. 
    // keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i
    // Gen creates a signature which proves that for some column in the keymatrix "pk"
    //   the signer knows a secret key for each row in that column
    // Ver verifies that the MG sig was created correctly        
    mgSig MLSAG_Gen(const key &message, const keyM & pk, const keyV & xx, const unsigned int index, size_t dsRows) {
        mgSig rv;
        size_t cols = pk.size();
        CHECK_AND_ASSERT_THROW_MES(cols >= 2, "Error! What is c if cols = 1!");
        CHECK_AND_ASSERT_THROW_MES(index < cols, "Index out of range");
        size_t rows = pk[0].size();
        CHECK_AND_ASSERT_THROW_MES(rows >= 1, "Empty pk");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_THROW_MES(pk[i].size() == rows, "pk is not rectangular");
        }
        CHECK_AND_ASSERT_THROW_MES(xx.size() == rows, "Bad xx size");
        CHECK_AND_ASSERT_THROW_MES(dsRows <= rows, "Bad dsRows size");

        size_t i = 0, j = 0, ii = 0;
        key c, c_old, L, R, Hi;
        sc_0(c_old.bytes);
        vector<geDsmp> Ip(dsRows);
        rv.II = keyV(dsRows);
        keyV alpha(rows);
        keyV aG(rows);
        rv.ss = keyM(cols, aG);
        keyV aHP(dsRows);
        keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
        toHash[0] = message;
        DP("here1");
        for (i = 0; i < dsRows; i++) {
            skpkGen(alpha[i], aG[i]); //need to save alphas for later..
            Hi = hashToPoint(pk[index][i]);
            aHP[i] = scalarmultKey(Hi, alpha[i]);
            toHash[3 * i + 1] = pk[index][i];
            toHash[3 * i + 2] = aG[i];
            toHash[3 * i + 3] = aHP[i];
            rv.II[i] = scalarmultKey(Hi, xx[i]);
            precomp(Ip[i].k, rv.II[i]);
        }
        size_t ndsRows = 3 * dsRows; //non Double Spendable Rows (see identity chains paper)
        for (i = dsRows, ii = 0 ; i < rows ; i++, ii++) {
            skpkGen(alpha[i], aG[i]); //need to save alphas for later..
            toHash[ndsRows + 2 * ii + 1] = pk[index][i];
            toHash[ndsRows + 2 * ii + 2] = aG[i];
        }

        c_old = hash_to_scalar(toHash);

        
        i = (index + 1) % cols;
        if (i == 0) {
            copy(rv.cc, c_old);
        }
        while (i != index) {

            rv.ss[i] = skvGen(rows);            
            sc_0(c.bytes);
            for (j = 0; j < dsRows; j++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                hashToPoint(Hi, pk[i][j]);
                addKeys3(R, rv.ss[i][j], Hi, c_old, Ip[j].k);
                toHash[3 * j + 1] = pk[i][j];
                toHash[3 * j + 2] = L; 
                toHash[3 * j + 3] = R;
            }
            for (j = dsRows, ii = 0; j < rows; j++, ii++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                toHash[ndsRows + 2 * ii + 1] = pk[i][j];
                toHash[ndsRows + 2 * ii + 2] = L;
            }
            c = hash_to_scalar(toHash);
            copy(c_old, c);
            i = (i + 1) % cols;
            
            if (i == 0) { 
                copy(rv.cc, c_old);
            }   
        }
        for (j = 0; j < rows; j++) {
            sc_mulsub(rv.ss[index][j].bytes, c.bytes, xx[j].bytes, alpha[j].bytes);
        }        
        return rv;
    }
    
    //Multilayered Spontaneous Anonymous Group Signatures (MLSAG signatures)
    //This is a just slghtly more efficient version than the ones described below
    //(will be explained in more detail in Ring Multisig paper
    //These are aka MG signatutes in earlier drafts of the ring ct paper
    // c.f. http://eprint.iacr.org/2015/1098 section 2. 
    // keyImageV just does I[i] = xx[i] * Hash(xx[i] * G) for each i
    // Gen creates a signature which proves that for some column in the keymatrix "pk"
    //   the signer knows a secret key for each row in that column
    // Ver verifies that the MG sig was created correctly            
    bool MLSAG_Ver(const key &message, const keyM & pk, const mgSig & rv, size_t dsRows) {

        size_t cols = pk.size();
        CHECK_AND_ASSERT_MES(cols >= 2, false, "Error! What is c if cols = 1!");
        size_t rows = pk[0].size();
        CHECK_AND_ASSERT_MES(rows >= 1, false, "Empty pk");
        for (size_t i = 1; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(pk[i].size() == rows, false, "pk is not rectangular");
        }
        CHECK_AND_ASSERT_MES(rv.II.size() == dsRows, false, "Bad II size");
        CHECK_AND_ASSERT_MES(rv.ss.size() == cols, false, "Bad rv.ss size");
        for (size_t i = 0; i < cols; ++i) {
          CHECK_AND_ASSERT_MES(rv.ss[i].size() == rows, false, "rv.ss is not rectangular");
        }
        CHECK_AND_ASSERT_MES(dsRows <= rows, false, "Bad dsRows value");

        for (size_t i = 0; i < rv.ss.size(); ++i)
          for (size_t j = 0; j < rv.ss[i].size(); ++j)
            CHECK_AND_ASSERT_MES(sc_check(rv.ss[i][j].bytes) == 0, false, "Bad ss slot");
        CHECK_AND_ASSERT_MES(sc_check(rv.cc.bytes) == 0, false, "Bad cc");

        size_t i = 0, j = 0, ii = 0;
        key c,  L, R, Hi;
        key c_old = copy(rv.cc);
        vector<geDsmp> Ip(dsRows);
        for (i = 0 ; i < dsRows ; i++) {
            precomp(Ip[i].k, rv.II[i]);
        }
        size_t ndsRows = 3 * dsRows; //non Double Spendable Rows (see identity chains paper
        keyV toHash(1 + 3 * dsRows + 2 * (rows - dsRows));
        toHash[0] = message;
        i = 0;
        while (i < cols) {
            sc_0(c.bytes);
            for (j = 0; j < dsRows; j++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                hashToPoint(Hi, pk[i][j]);
                addKeys3(R, rv.ss[i][j], Hi, c_old, Ip[j].k);
                toHash[3 * j + 1] = pk[i][j];
                toHash[3 * j + 2] = L; 
                toHash[3 * j + 3] = R;
            }
            for (j = dsRows, ii = 0 ; j < rows ; j++, ii++) {
                addKeys2(L, rv.ss[i][j], c_old, pk[i][j]);
                toHash[ndsRows + 2 * ii + 1] = pk[i][j];
                toHash[ndsRows + 2 * ii + 2] = L;
            }
            c = hash_to_scalar(toHash);
            copy(c_old, c);
            i = (i + 1);
        }
        sc_sub(c.bytes, c_old.bytes, rv.cc.bytes);
        return sc_isnonzero(c.bytes) == 0;  
    }
"""