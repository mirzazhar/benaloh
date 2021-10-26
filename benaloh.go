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
