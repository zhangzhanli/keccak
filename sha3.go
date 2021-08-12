package keccak

/*
https://csrc.nist.gov/csrc/media/publications/fips/202/final/documents/fips_202_draft.pdf
https://www.doc88.com/p-3764290587379.html
 */

import "hash"

func NewSHA3224() hash.Hash {
	return newKeccak(224 * 2, 224, domainSha3)
}

func NewSHA3256() hash.Hash {
	return newKeccak(256 * 2, 256, domainSha3)
}

func NewSHA3384() hash.Hash {
	return newKeccak(384 * 2, 384, domainSha3)
}

func NewSHA3512() hash.Hash {
	return newKeccak(512 * 2, 512, domainSha3)
}


func New224() hash.Hash {
	return newKeccak(224 * 2, 224, domainNone)
}

func New256() hash.Hash {
	return newKeccak(256 * 2, 256, domainNone)
}

func New384() hash.Hash {
	return newKeccak(384 * 2, 384, domainNone)
}

func New512() hash.Hash {
	return newKeccak(512 * 2, 512, domainNone)
}



// NewSHAKE128 returns a new hash.Hash computing SHAKE128 with a n * 8 bit output as specified in the FIPS 202 draft.
func NewSHAKE128(n int) hash.Hash {
	return newKeccak(128 * 2, n * 8, domainShake)
}

// NewSHAKE256 returns a new hash.Hash computing SHAKE256 with a n * 8 bit output as specified in the FIPS 202 draft.
func NewSHAKE256(n int) hash.Hash {
	return newKeccak(256 * 2, n * 8, domainShake)
}
