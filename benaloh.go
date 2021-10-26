package benaloh

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var one = big.NewInt(1)
var ErrLargeMessage = errors.New("benaloh: message is larger than the public key size")
var ErrLargeCipher = errors.New("benaloh: cipher is larger than the public key size")

// PrivateKey represents a Benaloh private key.
type PrivateKey struct {
	PublicKey
	PhiDivR, X *big.Int
}

// PublicKey represents Benaloh public key.
type PublicKey struct {
	Y, R, N *big.Int
}

// GenerateKey generates the Benaloh private key of the given bit size.
func GenerateKey(random io.Reader, bitsize int) (*PrivateKey, error) {
	zero := big.NewInt(0)

	for {
		// prime number p
		p, err := rand.Prime(random, bitsize)
		if err != nil {
			return nil, err
		}
		pminus1 := new(big.Int).Sub(p, one) // p-1

		// choose random number r, shuch that (p-1) should be
		// divible by r. Moreover, gcd(r, (p-1)/r) = 1.
		initr, err := rand.Prime(random, bitsize/2)
		if err != nil {
			return nil, err
		}
		rr := *initr
		r := &rr

		// quotient = (p-1)/r
		quotient, remainder := new(big.Int).DivMod(pminus1, initr, initr)
		// remainder should be zero
		if remainder.Cmp(zero) == 0 {
			gcd := new(big.Int).GCD(nil, nil, r, quotient)
			// gcd(r, (p-1)/r) = 1
			if gcd.Cmp(one) == 0 {
				for {
					// prime number q
					q, err := rand.Prime(random, bitsize)
					if err != nil {
						return nil, err
					}

					qminus1 := new(big.Int).Sub(q, one) //  q-1
					gcd = new(big.Int).GCD(nil, nil, qminus1, r)
					// Also, gcd(r, q-1) = 1.
					if gcd.Cmp(one) == 0 {
						// phi = (p-1)*(q-1)
						phi := new(big.Int).Mul(pminus1, qminus1)
						// n = p*q
						n := new(big.Int).Mul(p, q)
						// phidivr = phi/r
						phidivr := new(big.Int).Div(phi, r)

						for {
							// choose random integer y from {1...n-1}
							y, err := rand.Int(random, new(big.Int).Sub(n, one))
							if err != nil {
								return nil, err
							}

							// x = y^(phi/r) mod n
							x := new(big.Int).Mod(
								new(big.Int).Exp(y, phidivr, n),
								n,
							)
							// such that, x = y^(phi/r) mod n != 1
							if x.Cmp(one) == +1 {
								return &PrivateKey{
									PublicKey: PublicKey{
										Y: y,
										R: r,
										N: n,
									},
									X:       x,
									PhiDivR: phidivr,
								}, nil
							}
						}
					}
				}
			}
		}
	}
}

// Encrypt encrypts a plain text represented as a byte array. It returns
// an error if plain text value is larger than R value of Public key.
func (pub *PublicKey) Encrypt(plainText []byte) ([]byte, error) {
	u, err := rand.Int(rand.Reader, new(big.Int).Sub(pub.N, one))
	//u, err := rand.Prime(rand.Reader, pub.N.BitLen()) // prime no. can also be used
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(plainText)
	if m.Cmp(pub.R) == 1 { //  m < R
		return nil, ErrLargeMessage
	}

	// c = y^m * u^r mod n
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pub.Y, m, pub.N),
			new(big.Int).Exp(u, pub.R, pub.N),
		),
		pub.N,
	)

	return c.Bytes(), nil
}

// Decrypt decrypts the passed cipher text. It returns
// an error if cipher text value is larger than modulus N of Public key.
// Moreover, this works by taking discrete log of a base x to
// recover original message m. It can only work, if R is small.
// Otherwise, message can be recovered using Baby-step giant-step
// algorithm in case of large value of R.
func (priv *PrivateKey) Decrypt(cipherText []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(cipherText)

	if c.Cmp(priv.N) == 1 { // c < n
		return nil, ErrLargeCipher
	}

	// c^phi/r mod n
	a := new(big.Int).Exp(c, priv.PhiDivR, priv.N)

	// taking discret log of a base x. if R is small,
	// original message can be recovered by an exhaustive search,
	// i.e. checking if x^i mod n == a.
	for i := new(big.Int).Set(one); i.Cmp(priv.R) < 0; i.Add(i, one) {
		xa := new(big.Int).Exp(priv.X, i, priv.N)
		if xa.Cmp(a) == 0 {
			return i.Bytes(), nil
		}
	}
	return nil, nil
}

// HomomorphicEncTwo performs homomorphic operation over two chiphers.
// Benaloh has additive homomorphic property, so resultant cipher
// contains the sum of two numbers.
func (pub *PublicKey) HomomorphicEncTwo(c1, c2 []byte) ([]byte, error) {
	cipherA := new(big.Int).SetBytes(c1)
	cipherB := new(big.Int).SetBytes(c2)
	if cipherA.Cmp(pub.N) == 1 && cipherB.Cmp(pub.N) == 1 { // c < N
		return nil, ErrLargeCipher
	}

	// C = c1*c2 mod N
	C := new(big.Int).Mod(
		new(big.Int).Mul(cipherA, cipherB),
		pub.N,
	)
	return C.Bytes(), nil
}

// HommorphicEncMultiple performs homomorphic operation over two chiphers.
// Benaloh has additive homomorphic property, so resultant cipher
// contains the sum of multiple numbers.
func (pub *PublicKey) HommorphicEncMultiple(ciphers ...[]byte) ([]byte, error) {
	C := one

	for i := 0; i < len(ciphers); i++ {
		cipher := new(big.Int).SetBytes(ciphers[i])
		if cipher.Cmp(pub.N) == 1 { // c < N
			return nil, ErrLargeCipher
		}
		// C = c1*c2*c3...cn mod N
		C = new(big.Int).Mod(
			new(big.Int).Mul(C, cipher),
			pub.N,
		)
	}
	return C.Bytes(), nil
}
