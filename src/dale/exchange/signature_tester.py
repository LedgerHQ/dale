import hashlib
import sys
from ecdsa import VerifyingKey, curves, BadSignatureError
from ecdsa.util import sigdecode_der


# Ledger public keys for prod and test purposes
LEDGER_PUBLIC_KEY_PROD = bytearray.fromhex("040C17FDC5C0629ECA77E0A710CDE966BAE1A32C84E383E328A5521C281EFBA4990744EABCB591B0D8BE598A2FFACA8D29BC79FB20686CC7C0060C53862C5CE38C")
LEDGER_PUBLIC_KEY_TEST = bytearray.fromhex("0420DA62003C0CE097E33644A10FE4C30454069A4454F0FA9D4E84F45091429B5220AF9E35C0B2D9289380137307DE4DD1D418428CF21A93B33561BB09D88FE579")

def _check_signature(public_key, message, signature, curve) -> bool:
	vk = VerifyingKey.from_string(public_key, curve=curve)
	try:
		vk.verify(signature, message, hashlib.sha256, sigdecode=sigdecode_der)
	except BadSignatureError:
		return False
	return True

def check_ledger_prod_signature(message, signature) -> bool:
	return _check_signature(LEDGER_PUBLIC_KEY_PROD, message, signature, curves.SECP256k1)

def check_ledger_test_signature(message, signature) -> bool:
	return _check_signature(LEDGER_PUBLIC_KEY_TEST, message, signature, curves.SECP256k1)

def check_partner_signature(partner_key, message, signature, curve) -> bool:
	return _check_signature(partner_key, message, signature, curve)
