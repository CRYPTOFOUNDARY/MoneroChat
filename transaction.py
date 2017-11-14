"""
Author: Michael Davidson

Source/destination entries inspired by:
https://github.com/monero-project/monero/blob/master/src/cryptonote_core/cryptonote_tx_utils.h



Wallet functionality including transfer: 
https://github.com/monero-project/monero/blob/master/src/wallet/wallet2.cpp

TX Utilities
From: https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/cryptonote_format_utils.h
https://github.com/monero-project/monero/blob/master/src/cryptonote_basic/cryptonote_format_utils.cpp
--has encrypt/decrypt payment_id



From: https://github.com/monero-project/monero/blob/master/src/cryptonote_core/cryptonote_tx_utils.cpp
crypto::public_key get_destination_view_key_pub(const std::vector<tx_destination_entry> &destinations, const account_keys &sender_keys)
  {
    if (destinations.empty())
      return null_pkey;
    for (size_t n = 1; n < destinations.size(); ++n)
    {
      if (!memcmp(&destinations[n].addr, &sender_keys.m_account_address, sizeof(destinations[0].addr)))
        continue;
      if (destinations[n].amount == 0)
        continue;
      if (memcmp(&destinations[n].addr, &destinations[0].addr, sizeof(destinations[0].addr)))
        return null_pkey;
    }
    return destinations[0].addr.m_view_public_key;
  }

bool construct_tx(const account_keys& sender_account_keys, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time)
  {
     std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
     subaddresses[sender_account_keys.m_account_address.m_spend_public_key] = {0,0};
     crypto::secret_key tx_key;
     std::vector<crypto::secret_key> additional_tx_keys;
     return construct_tx_and_get_tx_key(sender_account_keys, subaddresses, sources, destinations, change_addr, extra, tx, unlock_time, tx_key, additional_tx_keys);
  }

bool construct_tx_and_get_tx_key(const account_keys& sender_account_keys, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, std::vector<tx_source_entry>& sources, const std::vector<tx_destination_entry>& destinations, const boost::optional<cryptonote::account_public_address>& change_addr, std::vector<uint8_t> extra, transaction& tx, uint64_t unlock_time, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys, bool rct)




From wallet2.h: https://github.com/monero-project/monero/blob/master/src/wallet/wallet2.h
struct tx_construction_data
    {
      std::vector<cryptonote::tx_source_entry> sources;
      cryptonote::tx_destination_entry change_dts;
      std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
      std::list<size_t> selected_transfers;
      std::vector<uint8_t> extra;
      uint64_t unlock_time;
      bool use_rct;
      std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
      uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer
    };

"""


class TxSource:

	def __init__(self, output_entry, outputs, real_output, real_out_tx_key, real_output_in_tx_index, amount, rct, mask, key_image, real_out_additional_tx_keys=None):
		self.output_entry = output_entry                                # (uint64_t, ctkey)
		self.outputs = outputs                                          # index + key + optional ringct commitment
		self.real_output = real_output                                  # index in outputs vector of real output_entry
		self.real_out_tx_key = real_out_tx_key                          # incoming real tx public key
		self.real_out_additional_tx_keys = real_out_additional_tx_keys
		self.real_output_in_tx_index = real_output_in_tx_index          # index in transaction outputs vector
		self.amount = amount                                            # money
		self.rct = rct						                            # true if the output is a ringct output
		self.mask = mask							                    # ringct amount mask 
		self.key_image = key_image										# double spend protection

	def clear(self):
		self.output_entry = None                  # (uint64_t, ctkey)
		self.outputs = {}                         # index + key + optional ringct commitment
		self.real_output = 0                      # index in outputs vector of real output_entry
		self.real_out_tx_key = None               # incoming real tx public key
		self.real_out_additional_tx_keys = None
		self.real_output_in_tx_index = 0          # index in transaction outputs vector
		self.amount = 0                           # money
		self.rct = False						  # true if the output is a ringct output
		self.mask = 0							  # ringct amount mask 
		self.key_image = None


class TxDestination:

	def __init__(self, amount, dest):
		self.amount = amount
		self.address = dest

	def clear(self):
		self.amount = 0
		self.address = ""

	def format_to_send(self):
		"""
		Returns dictionary format for easier transfers using the JSON RPC transfer function: {"amount": <>, "address": <>}
		"""
		return {"amount": self.amount, "address": self.address}


class Transaction:

	def __init__(self):
		self.version = 1
		self.unlock_time = 0
		self.vin = None
		self.vout = None
		self.extra = 0
		self.signatures = []
		self.type = None

	def clear(self):
		self.version = 1
		self.unlock_time = 0
		self.vin.clear()
		self.vout.clear()
		self.extra.clear()
		self.signatures.clear()
		self.type = 0