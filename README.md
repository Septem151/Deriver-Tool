# Deriver Tool

## Overview
The Deriver Tool functions as a standalone address deriver. Capable of deriving addresses from BIP44, BIP49, and BIP84 extended keys (`xpub`, `ypub`, and `zpub` respectively).

### Program Flow
```
Prompt for an account-level extended public key
IF Input == "Q"
	Exit Program
ELSE
	Prompt for an Address index
	IF Input == "Q"
		Return to Beginning of Program
	ELSE IF extended key is BIP44 (xpub)
		Display P2PKH address at given index
	ELSE IF extended key is BIP49 (ypub)
		Display P2SH-P2WPKH address at given index
	ELSE IF extended key is BIP84 (zpub)
		Display P2WPKH address at given index
```