package schnorr

import (
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSignVerify(t *testing.T) {
	//1. generate key pair
	sk, pk, tree, err := GenKeyPair(1, 32)
	require.NoError(t, err)

	round := uint64(10)
	//2. sign first message with round
	message := "block 1"
	hash := chainhash.HashH([]byte(message))
	signature, err := EOTSSign(sk, hash[:], round, tree)
	require.NoError(t, err)
	err = EOTSVerify(pk, signature, hash[:], round)
	require.NoError(t, err)

	//2. sign second message with round
	message = "block 2"
	hash2 := chainhash.HashH([]byte(message))
	signature2, err := EOTSSign(sk, hash2[:], round, tree)
	require.NoError(t, err)
	err = EOTSVerify(pk, signature2, hash2[:], round)
	require.NoError(t, err)

	//3. extract private_key from two signature
	sk1, err := EOTSExtract(pk, signature, hash[:], signature2, hash2[:])
	require.NoError(t, err)
	require.Equal(t, sk.Serialize(), sk1.Serialize())
	t.Log("origin    sk:", hex.EncodeToString(sk.Serialize()))
	t.Log("calculate sk:", hex.EncodeToString(sk1.Serialize()))
}

func testEOTSSign(b *testing.B, sk *EOTSPrivateKey, round uint64, pk *EOTSPublickey, tree *trie.Trie) {
	message := "block 1"
	hash := chainhash.HashH([]byte(message))

	signature, err := EOTSSign(sk, hash[:], round, tree)
	require.NoError(b, err)
	//t.Log("signature", signature.GetString())
	err = EOTSVerify(pk, signature, hash[:], round)
	require.NoError(b, err)

	//other message
	message = "block 2"
	hash2 := chainhash.HashH([]byte(message))
	signature2, err := EOTSSign(sk, hash2[:], round, tree)
	require.NoError(b, err)
	//t.Log("signature", signature2.GetString())
	err = EOTSVerify(pk, signature2, hash2[:], round)
	require.NoError(b, err)

	sk1, err := EOTSExtract(pk, signature, hash[:], signature2, hash2[:])
	require.NoError(b, err)
	require.Equal(b, sk.Serialize(), sk1.Serialize())

}

func BenchmarkEOTSSign(b *testing.B) {
	sk, pk, tree, err := GenKeyPair(0, 32)
	//sk, pk, err := GenKeyPairFromStr("fbf48e2da5abb2c3a827b1880780dcb7a4388a1ced169e83a0b2a1414b70222d")
	require.NoError(b, err)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		index := i % 32
		testEOTSSign(b, sk, uint64(index), pk, tree)
	}
	b.ReportAllocs()
}

func TestEOTSGen(t *testing.T) {
	now := time.Now()
	sk, pk, _, err := GenKeyPair(0, 65535)
	temp := time.Since(now)
	t.Log("time", temp.String())
	//sk, pk, err := GenKeyPairFromStr("fbf48e2da5abb2c3a827b1880780dcb7a4388a1ced169e83a0b2a1414b70222d")
	require.NoError(t, err)
	t.Log("sk:", hex.EncodeToString(sk.Serialize()))
	t.Log("pk", hex.EncodeToString(pk.PublicKey.SerializeCompressed()))
	t.Log("root", hex.EncodeToString(pk.root[:]))

}

func (s *Signature) GetString() string {
	var rBytes [32]byte
	s.r.PutBytesUnchecked(rBytes[:])
	var sBytes [32]byte
	s.s.PutBytesUnchecked(sBytes[:])
	return fmt.Sprintf("r:%s\ns:%s", hex.EncodeToString(rBytes[:]), hex.EncodeToString(sBytes[:]))
}
