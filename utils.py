"""
Author: Michael Davidson

To get H point for Pedersen Commitments:
https://github.com/monero-project/mininero/blob/master/GenLookup.py

Crypto functions (key derivation/generation, ring signatures): 
https://github.com/monero-project/monero/blob/master/src/crypto/crypto.cpp



----missing b58decode() 

def decode_addr(addr):
    '''Given address, get version and public spend and view keys.'''
    d = _b58.decode(addr)
    addr_checksum = d[-8:]
    calc_checksum = _cn.cn_fast_hash(d[:-8])[:8]
    if addr_checksum == calc_checksum:
        version = d[:2]
        publicSpendKey = d[2:66]
        publicViewKey = d[66:130]
        return version, publicSpendKey, publicViewKey
    else:
        return "Invalid Address", [], []

def decode_integrated_addr(addr):
    '''Given address, get version and public spend and view keys.'''
    d = _b58.decode(addr)
    addr_checksum = d[-8:]
    calc_checksum = _cn.cn_fast_hash(d[:-8])[:8]
    if addr_checksum == calc_checksum:
        version = d[:2]
        publicSpendKey = d[2:66]
        publicViewKey = d[66:130]
        paymentID = d[130:146]
        return version, publicSpendKey, publicViewKey, paymentID
    else:
        return "Invalid Address", [], []


def make_integrated_addr(addr, paymentID=None):
    '''Given address and 64-bit payment ID, generate integrated address.'''
    if paymentID == None:
        paymentID = _utils.gen_payment_id('integrated')
    _, psk, pvk = decode_addr(addr)
    vers = '13'
    return encode_integrated_addr(vers, psk, pvk, paymentID)

def account_from_spend_key(sk, acct_type='simplewallet'):
    '''Given a private spend key, derive private view key and address.
    Inputs:
      - sk (str) -- private spend key
      - acct_type (str, optional) -- 'simplewallet' (default) OR 'mymonero'
    Example:
      sk, vk, addr = account_from_seed(seed)
    Outputs:
      - sk (str) -- private spend key
      - vk (str) -- private view key
      - addr (str) -- Monero address
    '''
    if acct_type == 'mymonero':
        sk_hashed = _cn.cn_fast_hash(sk)
        vk = get_view_key(sk_hashed)
        sk = _cn.sc_reduce(sk_hashed)
    elif acct_type == 'simplewallet':
        sk = _cn.sc_reduce(sk)
        vk = get_view_key(sk)
    else:
        raise Exception("Account type not valid.")

    pk = _cn.public_from_secret(sk)
    pvk = _cn.public_from_secret(vk)

    addr = encode_addr(ADDRESS_VERSION, pk, pvk)

    return sk, vk, addr

def account_from_seed(seed, acct_type='simplewallet'):
    '''Given a wallet seed, derive private spend and view keys and address.
    Inputs:
      - seed (list) -- list of seed words from which to derive account info
      - acct_type (str, optional) -- 'simplewallet' (default) OR 'mymonero'
    Example:
      sk, vk, addr = account_from_seed(seed)
    Outputs:
      - sk (str) -- private spend key
      - vk (str) -- private view key
      - addr (str) -- Monero address
    '''
    sk = _mn.mn_decode(seed)
    return account_from_spend_key(sk, acct_type)
"""

import requests
import json
import random
import mininero as mini



####################################### FROM MoneroPy #####################################################
### https://github.com/bigreddmachine/MoneroPy/blob/master/moneropy/account.py ############################

def encode_integrated_addr(version, publicSpendKey, publicViewKey, paymentID):
    '''Given address version, public spend and view keys, and 64-bit payment ID, derive address.'''
    data = version + publicSpendKey + publicViewKey + paymentID
    checksum = mini.cn_fast_hash(data)
    return mini.b58encode(data + checksum[0:8])




############################################################################################################
############################################################################################################


def Hs(data):
	"""
	Hash to scalar. Hashes input data using keccak and then reduces the result mod l,
	returning a 32-byte scalar value.
	"""
	tmp = mini.cn_fast_hash(data)
	return mini.sc_reduce_key(tmp)

def Hp(data):
	"""
	Hash to point. Takes arbitrary data, hex encodes it, and then applies a 
	hash function that outputs a valid point on the Ed25519 curve.
	"""
	hexval = mini.intToHex(data)
	return mini.hashToPointCN(hexval)

def randomScalar(n=256):
	"""
	Generates a cryptographically secure random n-bit scalar value
	"""
	tmp = random.SystemRandom().getrandbits(n)
	return tmp

def randomHex(n=256):
	"""
	Generates a cryptographically secure n-bit hex value
	"""
	tmp = randomScalar(n)
	return mini.sc_reduce_key(tmp)

def format_amounts(num):
	"""
	Input: An integer representing minimal unit of monero
	Output: User friendly representation of the amount in units of XMR
	"""
	X = 12
	if len(num) < X + 1:
		# Pad with zeros
		num = '0' * (X + 1 - len(num)) + num
	index = len(num) - X
	num = num[0:index] + '.' + num[index:]
	return num


def to_atomic(amount):
	"""
	Given an amount of XMR, return the integer number of atomic units.
	"""
	return int(amount * 1000000000000)

def to_xmr(amount):
	"""
	Given an integer number of atomic units, convert to the more human-readable # of coins.
	"""
	return amount / 1000000000000.0



URL = 'http://localhost:28082/json_rpc'
URL_gettx = 'http://localhost:28081/gettransactions'
URL_rawtx = 'http://localhost:28081/sendrawtransaction'
HEADER = {"content-type": "application/json"}
RPC = {"jsonrpc": "2.0", "id": "0"}

def curl(data):
	"""
	Makes a request to the JSON-RPC wallet using information provided
	Inputs:
	-data is a dictionary that includes the key "method" and optionally "params"
	Outputs:
	-Requests module response object in JSON format
	"""
	payload = data
	payload.update(RPC)
	try:
		r = requests.post(URL, data=json.dumps(payload), headers=HEADER)
		r = r.json()
		if "error" in r:
			return r["error"]
		elif "results" in r:
			return r["results"]
		elif "result" in r:
			return r["result"]
	except:
		print("Failed to post cURL request.")

def curl_gettx(txs_hashes, decode=True):
	"""
	An alternative method of getting transaction information from the Monero daemon instead of the wallet.
	Inputs:
		txs_hashes = list of transaction IDs to fetch info on.
		decode = boolean; if true, return JSON formatted info. If False, returns binary blob.
	Outputs:
		status - General RPC error code. "OK" means everything looks good.
		txs_as_hex - string; Full transaction information as a hex string.
		txs_as_json - json string; (Optional - returned if set in inputs.) List of transaction info:
			version - Transaction version
			unlock_time - If not 0, this tells when a transaction output is spendable.
			vin - List of inputs into transaction:
				key - The public key of the previous output spent in this transaction.
					amount - The amount of the input, in atomic units.
					key_offsets - A list of integer offets to the input.
					k_image - The key image for the given input
			vout - List of outputs from transaction:
				amount - Amount of transaction output, in atomic units.
				target - Output destination information:
					key - The stealth public key of the receiver. Whoever owns the private key associated with this key controls this 
					transaction output.
			extra - Usually called the "payment ID" but can be used to include any random 32 bytes.
			signatures - List of ignatures used in ring signature to hide the true origin of the transaction.
	"""
	payload = {"txs_hashes": txs_hashes, "decode_as_json": decode}
	try:
		r = requests.post(URL_gettx, data=json.dumps(payload), headers=HEADER)
		r = r.json()
		return r
	except:
		print("Failed RPC call to /gettransactions.")

def curl_send_raw(tx_as_hex):
	"""
	Broadcasts a raw hex transaction blob to the Monero daemon. Takes hex string as input and returns a status code.
	"""
	payload = {"tx_as_hex": tx_as_hex}
	try:
		r = requests.post(URL_rawtx, data=json.dumps(payload), headers=HEADER)
		r = r.json()
		if "error" in r:
			return r["error"]
		elif "status" in r:
			return r["status"]
	except:
		print("Failed to send raw transaction.")