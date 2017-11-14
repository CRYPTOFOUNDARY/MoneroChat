#!/usr/bin/env python

"""
Author: Michael Davidson

Library for some general Monero functionality:
https://github.com/bigreddmachine/MoneroPy/tree/master/moneropy


-Use this keccak: https://github.com/monero-project/mininero/blob/master/Keccak.py
-Helper functions (hashToPoint, encodings, etc.): 
https://github.com/monero-project/mininero/blob/master/mininero.py


^^See this note about using ECC with Monero:
https://monero.stackexchange.com/questions/2290/why-how-does-monero-generate-public-ed25519-keys-without-using-the-standard-publ

Double Ratchet Python Library: https://github.com/rxcomm/pyaxo
Borromean Ring Sigs: https://github.com/AdamISZ/borring


Possible libraries for Ed25519:
--PyNaCl does everything needed and works similarly to Cryptography library
https://pynacl.readthedocs.io/en/latest/

try:
	from cryptography.hazmat.backends import default_backend
	from cryptography.hazmat.primitives.asymmetric import x25519
	from cryptography.hazmat.primitives import hmac, hashes
	from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except:
	print 'Need Cryptography library: pip install cryptography'
"""
import sys
import argparse
import os
import threading
import binascii
import json
import struct
import hashlib
import hmac
# HKDF can be done using the above two standard libraries: https://en.wikipedia.org/wiki/HKDF
# https://docs.python.org/2.7/library/hmac.html
# https://docs.python.org/2.7/library/hashlib.html
# EC stuff based off this: https://github.com/bigreddmachine/MoneroPy/tree/master/moneropy/crypto

import requests

import utils
import address_book
import transaction

#IP = '127.0.0.1'
#PORT = 28082
#URL = 'http://localhost:28082/json_rpc'
#HEADER = {"content-type": "application/json"}
#RPC = {"jsonrpc": "2.0", "id": "0"}


class FailedSend(Exception):
	"""JSON RPC call using "transfer" method failed."""


class Transfer:
	"""For use with incoming_transfers() and get_transfer_by_txid()"""
	def __init__(self, **kwargs):
		"""Initialize using Transfer(**argsdict) """
		self.amount = kwargs["amount"] if "amount" in kwargs else 0
		self.spent = kwargs["spent"] if "spent" in kwargs else False # boolean, False if user hasn't spent it from wallet
		self.index = kwargs["global_index"] if "global_index" in kwargs else -1# int, global index of the transaction
		self.tx_size = kwargs["tx_size"] if "tx_size" in kwargs else -1 # transaction size in bytes
		self.fee = kwargs["fee"] if "fee" in kwargs else 0 # miner's fee
		self.height = kwargs["height"] if "height" in kwargs else -1 # block height of this transfer
		self.note = kwargs["note"] if "note" in kwargs else "" # text description of payment
		self.timestamp = kwargs["timestamp"]  if "timestamp" in kwargs else None
		self.type = kwargs["type"] if "type" in kwargs else None # in/out/pending/failed/pool
		self.payment_id = kwargs["payment_id"] if "payment_id" in kwargs else "0000000000000000"
		self.unlock_time = kwargs["unlock_time"] if "unlock_time" in kwargs else 0
		self.destinations = kwargs["destinations"] if "destinations" in kwargs else []
		# Transaction hash or transaction ID are the same, but different calls call them different things.
		if "tx_hash" in kwargs:
			self.txid = kwargs["tx_hash"]
		elif "txid" in kwargs:
			self.txid = kwargs["txid"]
		else:
			self.txid = ""




class Monero:

	def __init__(self, wallet_name, passwd=None):
		self.wallet_name = wallet_name
		self.passwd = passwd
		self.open_wallet()
		self.balance = 0
		self.unlocked_balance = 0
		self.address = ""
		self.height = 0 # Wallet's current block height
		self.incoming_tx_list = []
		self.available_tx_list = []
		self.key = "" # Private key
		self.get_address()
		self.get_height()
		self.get_balance()

	def load_address_book(self):
		"""
		Load encrypted address book from disk if it exists, or create a new one otherwise.
		"""
		pass


	#########################################################
	#########################################################
	#########################################################

	def open_wallet(self):
		"""
		Required in order to use the wallet.
		"""
		cmd = {"method": "open_wallet", "params": {"filename": self.wallet_name, "password": self.passwd}}
		utils.curl(cmd)

	def stop_wallet(self):
		"""
		Shuts down the monero-wallet-rpc.exe process
		"""
		cmd = {"method": "stop_wallet"}
		utils.curl(cmd)

	def get_balance(self):
		"""
		Updates the balance and unlocked balance of the open wallet.
		"""
		cmd = {"method": "getbalance"}
		r = utils.curl(cmd)
		self.balance = r["balance"]
		self.unlocked_balance = r["unlocked_balance"]

	def get_address(self):
		"""
		Retrieves the 95-character hex address string of the wallet and saves it
		"""
		cmd = {"method": "getaddress"}
		r = utils.curl(cmd)
		self.address = r["address"]

	def get_height(self):
		"""
		Retrieves current block height.
		"""
		cmd = {"method": "getheight"}
		r = utils.curl(cmd)
		self.height = r["height"]

	def query_key(self, key_type="mnemonic"):
		"""
		Retrieves private spend or view key.

		Input
		key_type - string; Which key to retrieve: "mnemonic" - the mnemonic seed (older wallets do not have one) 
		OR "view_key" - the view key

		Output
		key - string; The view key will be hex encoded, while the mnemonic will be a string of words.
		"""
		cmd = {"method": "query_key", "params": {"key_type": key_type}}
		r = utils.curl(cmd)
		if r and "key" in r:
			self.key = r["key"]
			print(self.key)
		

	###########################################################
	###########################################################
	###########################################################


	def split_integrated_address(self, integrated_address):
		"""
		Retrieve the standard address and payment id corresponding to an integrated address

		Input
		integrated_address - string

		Outputs
		standard_address - string
		payment - string; hex encoded
		"""
		cmd = {"method": "split_integrated_address", "params": {"integrated_address": integrated_address}}
		r = utils.curl(cmd)
		if r:
			payment_id = r["payment_id"]
			address = r["standard_address"]
			return payment_id, address

	def get_payments(self, payment_ids, height):
		"""
		Get a list of incoming payments using a given payment id, or a list of payments ids, from a given height.
		Inputs
		payment_ids: array of strings representing payment IDs
		height:      block height to start looking for payments (unsigned int)
		Outputs
		payments - list of:
			payment_id - string
			tx_hash - string
			amount - unsigned int
			block_height - unsigned int
			unlock_time - unsigned int
		"""
		cmd = {"method": "get_bulk_payments", "params": {"payment_ids": payment_ids, "min_block_height": height}}
		r = utils.curl(cmd)
		if r and "payments" in r:
			payment_list = r["payments"]
			payments = [] # Store Payment objects here
			for p in payment_list:
				payment = Transfer(**p)
				payments.append(payment)
			return payments
		if r and "message" in r:
			print(r["message"])

	def get_incoming_transfers(self, transfer_type="all"):
		"""
		Retrieves list of incoming transfers to this wallet

		Input
		transfer_type - string; "all": all the transfers, "available": only transfers which are not yet spent, 
		OR "unavailable": only transfers which are already spent.

		Outputs
		transfers - list of:
			amount - unsigned int
			spent - boolean
			global_index - unsigned int; Mostly internal use, can be ignored by most users.
			tx_hash - string; Several incoming transfers may share the same hash if they were in the same transaction.
			tx_size - unsigned int
		"""
		cmd = {"method": "incoming_transfers", "params": {"transfer_type": transfer_type}}
		r = utils.curl(cmd)
		if r and "transfers" in r:
			tx_list = r["transfers"]
			for t in tx_list:
				transfer = Transfer(**t)
				if transfer.spent == False:
					self.available_tx_list.append(transfer)
				self.incoming_tx_list.append(transfer)


	def get_transfer_by_txid(self, txid):
		"""
		Retrieve information about a transfer to/from this wallet/address
		Inputs
		txid: string
		Outputs
		transfer - JSON object containing parment information:
			amount - unsigned int
			fee - unsigned int
			height - unsigned int
			note - string
			payment_id - string
			timestamp - unsigned int
			txid - string
			type - string
		"""
		cmd = {"method": "get_transfer_by_txid", "params": {"txid": txid}}
		r = utils.curl(cmd)
		if r and "transfer" in r:
			#amount = r["amount"]
			#fee = r["fee"]
			#height = r["height"]
			#note = r["note"]
			#payment_id = r["payment_id"]
			#timestamp = r["timestamp"]
			#tx_hash = r["txid"]
			#tx_type = r["type"]
			transfer = Transfer(**(r["transfer"]))
			return transfer

	def get_transfers(self, **kwargs):
		"""
		Returns a list of transfers

		Inputs
			in - boolean;
			out - boolean;
			pending - boolean;
			failed - boolean;
			pool - boolean;
			filter_by_height - boolean;
			min_height - unsigned int;
			max_height - unsigned int;
		Outputs
		in array of transfers
		out array of transfers
		pending array of transfers
		failed array of transfers
		pool array of transfers
			txid - string;
			payment_id - string;
			height - unsigned int;
			timestamp - unsigned int;
			amount - unsigned int;
			fee - unsigned int;
			note - string;
			destinations - std::list;
			type - string;
		"""
		types = ["in", "out", "pending", "failed", "pool"]
		transfer_list = []
		cmd = {"method": "get_transfers", "params": kwargs}
		r = utils.curl(cmd)
		if r and "message" in r:
			print(r["message"])
		elif any(test in r for test in types):
			for key in r: # key = type, value = list of transfers
				v = r[key]
				for t in v: # for each individual transfer in the vector for that type
					transfer = Transfer(**t)
					transfer_list.append(transfer)
		return transfer_list


	def send(self, **kwargs):
		"""
		Send monero to a number of recipients. Wraps the "transfer" method.
		Inputs:
			destinations - array of destinations to receive XMR:
				amount - unsigned int; Amount to send to each destination, in atomic units.
				address - string; Destination public address.
			fee - unsigned int; Ignored, will be automatically calculated.
			mixin - unsigned int; Number of outpouts from the blockchain to mix with (0 means no mixing).
			unlock_time - unsigned int; Number of blocks before the monero can be spent (0 to not add a lock).
			payment_id - string; (Optional) Random 32-byte/64-character hex string to identify a transaction.
			get_tx_key - boolean; (Optional) Return the transaction key after sending.
			priority - unsigned int; Set a priority for the transaction. Accepted Values are: 0-3 for: default, unimportant, normal, elevated, priority.
			do_not_relay - boolean; (Optional) If true, the newly created transaction will not be relayed to the monero network. (Defaults to false)
			get_tx_hex - boolean; Return the transaction as hex string after sending
		Outputs:
			fee - Integer value of the fee charged for the txn.
			tx_hash - String for the publically searchable transaction hash
			tx_key - String for the transaction key if get_tx_key is true, otherwise, blank string.
			tx_blob - Transaction as hex string if get_tx_hex is true
		"""
		cmd = {"method": "transfer", "params": kwargs}
		r = utils.curl(cmd)
		if r and "message" in r:
			error = r["message"]
			raise FailedSend(error)
		elif r:
			fee = r["fee"]
			txid = r["tx_hash"]
			tx_key = r["tx_key"]
			tx_blob = r["tx_blob"]
			return fee, txid, tx_key, tx_blob

	def basic_transfer(self, destination, payment_id=None):
		"""
		Simpler to use interface for sending monero with default values if only sending to a single destination.
		Inputs:
			destinations = TxDestination object
			payment_id = Optional
		Outputs:
			See send()
		"""
		d = destination.format_to_send()
		cmd = {"destinations": [d], "mixin": 4, "unlock_time": 0, "priority": 1, "get_tx_hex": True, "get_tx_key": True}
		if payment_id:
			cmd["payment_id"] = payment_id
		try:
			fee, txid, tx_key, tx_blob = self.send(**cmd)
			return fee, txid, tx_key, tx_blob
		except:
			print("Basic transfer failed.")

	def send_to_self(self, amount, payment_id=None):
		"""
		Send monero from open wallet to itself. Mostly for testing purposes.
		"""
		if self.address and amount <= self.unlocked_balance:
			dest = transaction.TxDestination(amount, self.address)
			try:
				fee, txid, tx_key, tx_blob = self.basic_transfer(dest, payment_id)
				print("fee: %s\ntxid: %s\ntx_key: %s\ntx_blob: %s" % (str(fee), str(txid), str(tx_key), str(tx_blob)))
			except:
				print("Failed to send to self.")


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-w', '--wallet', dest='wallet')
	parser.add_argument('-p', '--password', dest='passwd')
	args = parser.parse_args()
	monero = Monero(args.wallet, args.passwd)
	print("Balance: %s\nUnlocked: %s" % (str(monero.balance), str(monero.unlocked_balance)))
	monero.send_to_self(1000000)
	monero.get_balance()
	print("Balance: %s\nUnlocked: %s" % (str(monero.balance), str(monero.unlocked_balance)))