"""
Author: Michael Davidson

"""
# All relevant info for each entry is stored in the description field as a string "{}" of JSON formatted info.
# This should cover all info needed for the axolotl/double ratchet algorithm

import utils
import json


class Entry:
	"""Stores data for a given address book entry and manages Axolotl algorithm."""

	def __init__(self, address, payment_id="", description=""):
		self.address = address
		self.payment_id = payment_id
		self.description = description # description contains a string representation of JSON encoded info for axolotl
		self.viewkey = None
		self.spendkey = None

	def get_addr(self):
		return self.address

	def set_addr(self, address):
		self.address = address

	def get_id(self):
		return self.payment_id

	def set_id(self, payment_id):
		self.payment_id = payment_id

	def get_desc(self):
		return self.description

	def set_desc(self, description):
		self.description = description

	def update_kdf_chain(self):
		pass





class AddressBook:
	"""
	The state of the address book should be stored on disk encrypted using the wallet 
	password. This way it can be loaded when the client starts up.
	"""
	def __init__(self):
		self.count = 0 # number of entries in address book
		self.entries = {} # key: index; value: Entry object


	def get_address_book(self, entries=[]):
		"""
		Retrieves entries from the address book

		Input
		entries - array of unsigned int; indices of the requested address book entries

		Output
		entries - array of entries:
			address - string;
			description - string;
			index - unsigned int;
			payment_id - string;
		"""
		cmd = {"method": "get_address_book", "params": {"entries": entries}}
		r = utils.curl(cmd)
		if r:
			# TODO: Actually store the addresses
			addresses = r["entries"]


	def add_entry(self, entry):
		pass

	def add_address_book(self, address, payment_id="", description=""):
		"""
		Adds new entry to address book

		Inputs
		address - string;
		payment_id - (optional) string, defaults to "0000000000000000000000000000000000000000000000000000000000000000";
		description - (optional) string, defaults to ""

		Output
		index - unsigned int; The index of the address book entry.
		"""
		# TODO: Handle cases where description/payment id aren't provided
		cmd = {"method": "add_address_book", "params": {"address": address, "payment_id": payment_id, "description": description}}
		r = utils.curl(cmd)
		if r:
			index = r["index"]
			return index

	def delete_address_book(self, index):
		"""
		Deletes and address book entry.

		Input
		index - int, the index to be deleted.
		"""
		cmd = {"method": "delete_address_book", "params": {"index": index}}
		utils.curl(cmd)
