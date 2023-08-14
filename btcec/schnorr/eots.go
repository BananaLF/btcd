package schnorr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa_schnorr "github.com/decred/dcrd/dcrec/secp256k1/v4/schnorr"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
)

type EOTSPublickey struct {
	*btcec.PublicKey
	root chainhash.Hash
}

type EOTSPrivateKey struct {
	*btcec.PrivateKey
}

type EOTSSignature struct {
	*Signature
	proof proofList
}

func GenKeyPair(start, end uint64) (*EOTSPrivateKey, *EOTSPublickey, *trie.Trie, error) {
	sk, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	pk := sk.PubKey()

	privateKey := EOTSPrivateKey{sk}

	//randTree, tdb, err := OpenLevelDBTrie("./testdata/", "randtree", 1024, 1024)
	randTree, tdb, err := OpenMemoryDBTrie()
	if err != nil {
		return nil, nil, nil, err
	}
	root, err := GenRandTree(&privateKey, randTree, tdb, start, end)
	if err != nil {
		return nil, nil, nil, err
	}
	publicKey := EOTSPublickey{pk, chainhash.Hash(root)}

	return &privateKey, &publicKey, randTree, nil
}

func GenKeyPairFromStr(str string, start, end uint64) (*EOTSPrivateKey, *EOTSPublickey, *trie.Trie, error) {
	pbytes, err := hex.DecodeString(str)
	if err != nil {
		return nil, nil, nil, err
	}
	sk, pk := btcec.PrivKeyFromBytes(pbytes)

	privateKey := EOTSPrivateKey{sk}

	//randTree, tdb, err := OpenLevelDBTrie("./testdata/", "randtree", 1024, 1024)
	randTree, tdb, err := OpenMemoryDBTrie()
	if err != nil {
		return nil, nil, nil, err
	}
	root, err := GenRandTree(&privateKey, randTree, tdb, start, end)
	if err != nil {
		return nil, nil, nil, err
	}
	publicKey := EOTSPublickey{pk, chainhash.Hash(root)}

	return &privateKey, &publicKey, randTree, nil
}

func OpenLevelDBTrie(dir, namespace string, cache, handles int) (*trie.Trie, *trie.Database, error) {
	db, err := rawdb.NewLevelDBDatabase(dir, cache, handles, namespace, false)
	if err != nil {
		return nil, nil, err
	}
	tdb := trie.NewDatabase(db)
	randTree := trie.NewEmpty(tdb)
	return randTree, tdb, nil
}
func OpenMemoryDBTrie() (*trie.Trie, *trie.Database, error) {
	db := rawdb.NewMemoryDatabase()
	tdb := trie.NewDatabase(db)
	randTree := trie.NewEmpty(tdb)
	return randTree, tdb, nil
}

func GenRandTree(privateKey *EOTSPrivateKey, randTree *trie.Trie, tdb *trie.Database, start, end uint64) (root [32]byte, err error) {
	for i := start; i < end; i++ {
		roundBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(roundBytes, i)
		r, err := generateR(privateKey, i)
		if err != nil {
			return root, err
		}
		if err := randTree.Update(roundBytes[:], r[:]); err != nil {
			return root, err
		}
	}

	root, nodes := randTree.Commit(false)
	if nodes != nil {
		if err := tdb.Update(root, types.EmptyRootHash, trienode.NewWithNodeSet(nodes)); err != nil {
			return root, err
		}
		if err := tdb.Commit(root, false); err != nil {
			return root, err
		}
	}

	return root, nil
}

func EOTSSign(privKey *EOTSPrivateKey, hash []byte, round uint64, randTree *trie.Trie) (*EOTSSignature, error) {
	// First, parse the set of optional signing options.
	opts := defaultSignOptions()

	roundHash := roundHash(round)

	// The algorithm for producing a BIP-340 signature is described in
	// README.md and is reproduced here for reference:
	//
	// G = curve generator
	// n = curve order
	// d = private key
	// m = message
	// a = input randmoness
	// r, s = signature
	//
	// 1. d' = int(d)
	// 2. Fail if m is not 32 bytes
	// 3. Fail if d = 0 or d >= n
	// 4. P = d'*G
	// 5. Negate d if P.y is odd
	// 6. t = bytes(d) xor tagged_hash("BIP0340/aux", t || bytes(P) || m)
	// 7. rand = tagged_hash("BIP0340/nonce", a)
	// 8. k' = int(rand) mod n
	// 9. Fail if k' = 0
	// 10. R = 'k*G
	// 11. Negate k if R.y id odd
	// 12. e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || mod) mod n
	// 13. sig = bytes(R) || bytes((k + e*d)) mod n
	// 14. If Verify(bytes(P), m, sig) fails, abort.
	// 15. return sig.
	//
	// Note that the set of functional options passed in may modify the
	// above algorithm. Namely if CustomNonce is used, then steps 6-8 are
	// replaced with a process that generates the nonce using rfc6679. If
	// FastSign is passed, then we skip set 14.

	// Step 1.
	//
	// d' = int(d)
	var privKeyScalar btcec.ModNScalar
	privKeyScalar.Set(&privKey.Key)

	// Step 2.
	//
	// Fail if m is not 32 bytes
	if len(hash) != scalarSize {
		str := fmt.Sprintf("wrong size for message hash (got %v, want %v)",
			len(hash), scalarSize)
		return nil, signatureError(ecdsa_schnorr.ErrInvalidHashLen, str)
	}

	// Step 3.
	//
	// Fail if d = 0 or d >= n
	if privKeyScalar.IsZero() {
		str := "private key is zero"
		return nil, signatureError(ecdsa_schnorr.ErrPrivateKeyIsZero, str)
	}

	// Step 4.
	//
	// P = 'd*G
	pub := privKey.PubKey()

	// Step 5.
	//
	// Negate d if P.y is odd.
	pubKeyBytes := pub.SerializeCompressed()
	if pubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	kPrime, err := generateK(privKeyScalar, pubKeyBytes, roundHash)
	if err != nil {
		return nil, err
	}
	sig, err := schnorrSign(&privKeyScalar, kPrime, pub, hash, opts)
	kPrime.Zero()
	if err != nil {
		return nil, err
	}

	var proof proofList
	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, round)
	err = randTree.Prove(roundBytes[:], 0, &proof)
	if err != nil {
		return nil, err
	}
	eotsSign := EOTSSignature{Signature: sig, proof: proof}
	return &eotsSign, nil

}

func EOTSVerify(publicKey *EOTSPublickey, signature *EOTSSignature, hash []byte, round uint64) error {
	signatureSucccess := signature.Verify(hash, publicKey.PublicKey)
	if !signatureSucccess {
		return errors.New("signatrue verify failed")
	}
	var rBytes [32]byte
	signature.r.PutBytesUnchecked(rBytes[:])

	proof := memorydb.New()
	for i, _ := range signature.proof {
		err := proof.Put(crypto.Keccak256(signature.proof[i]), signature.proof[i])
		if err != nil {
			return err
		}
	}
	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, round)
	calculate_r, err := trie.VerifyProof(common.BytesToHash(publicKey.root[:]), roundBytes[:], proof)
	if err != nil {
		return err
	}

	if bytes.Compare(calculate_r, rBytes[:]) != 0 {
		return errors.New(fmt.Sprintf("the r of signature is not round %d r. \n\texpect:%s \n\tgot:%s", round, hex.EncodeToString(calculate_r), hex.EncodeToString(rBytes[:])))
	}
	return nil
}

func EOTSExtract(publicKey *EOTSPublickey, signatureA *EOTSSignature, hashA []byte, signatureB *EOTSSignature, hashB []byte) (*btcec.PrivateKey, error) {
	//eA
	eA, err := generateE(publicKey, &signatureA.r, hashA)
	if err != nil {
		return nil, err
	}

	//eB
	eB, err := generateE(publicKey, &signatureB.r, hashB)
	if err != nil {
		return nil, err
	}

	//sA = k + d*eA
	//sB = k + d*eB
	sA := &signatureA.s
	//-sB
	sB := &signatureB.s

	key, err := recover(sA, sB, eA, eB)
	if err != nil {
		return nil, err
	}
	if publicKey.SerializeCompressed()[0] == secp.PubKeyFormatCompressedOdd {
		key = new(btcec.ModNScalar).NegateVal(key)
	}
	return &btcec.PrivateKey{Key: *key}, nil
}

func recover(sA, sB, eA, eB *btcec.ModNScalar) (*btcec.ModNScalar, error) {
	eB = new(btcec.ModNScalar).NegateVal(eB)

	//sA = k + d*eA
	//sB = k + d*eB
	//-sB
	sB = new(btcec.ModNScalar).NegateVal(sB)

	//sA-sB = d(eA-eB)
	sAsubsB := new(btcec.ModNScalar).Add2(sA, sB)

	eAsubeB := new(btcec.ModNScalar).Add2(eA, eB)
	eAsubeB_temp := new(btcec.ModNScalar).InverseValNonConst(eAsubeB)

	privKey := new(btcec.ModNScalar).Mul2(eAsubeB_temp, sAsubsB)

	return privKey, nil
}

func roundHash(round uint64) chainhash.Hash {
	roundBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(roundBytes, round)
	return chainhash.HashH(roundBytes)
}

func generateR(privKey *EOTSPrivateKey, round uint64) ([32]byte, error) {
	var rBytes [32]byte
	roundHash := roundHash(round)

	// d' = int(d)
	var privKeyScalar btcec.ModNScalar
	privKeyScalar.Set(&privKey.Key)

	// Fail if d = 0 or d >= n
	if privKeyScalar.IsZero() {
		str := "private key is zero"
		return rBytes, signatureError(ecdsa_schnorr.ErrPrivateKeyIsZero, str)
	}

	// P = 'd*G
	pub := privKey.PubKey()

	// Negate d if P.y is odd.
	pubKeyBytes := pub.SerializeCompressed()
	if pubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	k, err := generateK(privKeyScalar, pubKeyBytes, roundHash)
	if err != nil {
		return rBytes, err
	}

	// R = kG
	var R btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(k, &R)

	// Step 11.
	//
	// Negate nonce k if R.y is odd (R.y is the y coordinate of the point R)
	//
	// Note that R must be in affine coordinates for this check.
	R.ToAffine()
	if R.Y.IsOdd() {
		k.Negate()
	}
	r := &R.X
	r.PutBytesUnchecked(rBytes[:])
	return rBytes, nil
}

func generateK(privKeyScalar btcec.ModNScalar, pubKeyBytes []byte, roundHash chainhash.Hash) (*btcec.ModNScalar, error) {
	// At this point, we check to see if a CustomNonce has been passed in,
	// and if so, then we'll deviate from the main routine here by
	// generating the nonce value as specifid by BIP-0340.

	// Step 6.
	//
	// t = bytes(d) xor tagged_hash("BIP0340/aux", a)
	privBytes := privKeyScalar.Bytes()
	t := chainhash.TaggedHash(
		chainhash.TagBIP0340Aux, roundHash[:],
	)
	for i := 0; i < len(t); i++ {
		t[i] ^= privBytes[i]
	}

	// Step 7.
	//
	// rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m)
	//
	// We snip off the first byte of the serialized pubkey, as we
	// only need the x coordinate and not the market byte.
	rand := chainhash.TaggedHash(
		chainhash.TagBIP0340Nonce, t[:], pubKeyBytes[1:], chainhash.HashB(roundHash[:]),
	)

	// Step 8.
	//
	// k'= int(rand) mod n
	var kPrime btcec.ModNScalar
	kPrime.SetBytes((*[32]byte)(rand))

	// Step 9.
	//
	// Fail if k' = 0
	if kPrime.IsZero() {
		str := fmt.Sprintf("generated nonce is zero")
		return nil, signatureError(ecdsa_schnorr.ErrSchnorrHashValue, str)
	}
	return &kPrime, nil
}

func generateE(publicKey *EOTSPublickey, r *btcec.FieldVal, hash []byte) (*btcec.ModNScalar, error) {
	pubKey := publicKey.PublicKey
	pBytes := SerializePubKey(pubKey)

	var rBytes [32]byte
	r.PutBytesUnchecked(rBytes[:])

	commitment := chainhash.TaggedHash(
		chainhash.TagBIP0340Challenge, rBytes[:], pBytes, hash,
	)

	var e btcec.ModNScalar
	if overflow := e.SetBytes((*[32]byte)(commitment)); overflow != 0 {
		str := "hash of (r || P || m) too big"
		return nil, signatureError(ecdsa_schnorr.ErrSchnorrHashValue, str)
	}
	return &e, nil
}

type proofList [][]byte

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, value)
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}
