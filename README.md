# Benaloh Cryptosystem
This package is implemented according to the pseudo-code and mathematical notations of the following algorithms of the Benaloh cryptosystem:
 - Key Generation
 - Encryption
 - Decryption

Benaloh has [additive homomorphic encryption property](https://dl.acm.org/doi/pdf/10.1145/3214303) and is an example of Partially Homomorphic Encryption (PHE). Therefore, the multiplication of ciphers results in the sum of original numbers.

Moreover, it also supports the following PHE functions:
- Homomorphic Encryption over two ciphers
- Homomorphic Encryption over multiple ciphers



## Installation
```sh
go get -u github.com/Mirzazhar/benaloh
```
## Warning
This package is intendedly designed for education purposes. Of course, it may contain bugs and needs several improvements. Therefore, this package should not be used for production purposes.
> :warning: **Keys generation implementation is not efficient and it takes time to generate keys using large primes. The worst thing, it can generate keys up to the 32-bit size of prime numbers**
## Limitations
In this implementation decryption algorithm works by taking the discrete log of a base x to recover original message m. It can only work if the value of R in the key is small. Otherwise, message m can be recovered using [Baby-step giant-step algorithm](https://en.wikipedia.org/wiki/Baby-step_giant-step) in case of a large value of R.
## Usage & Examples
## Contribution
* You can fork this, extend it and contribute back.
* You can contribute with pull requests.
## LICENSE
MIT License
## References
1. https://en.wikipedia.org/wiki/Benaloh_cryptosystem
2. https://www.microsoft.com/en-us/research/wp-content/uploads/1987/01/thesis.pdf
3. https://dl.acm.org/doi/pdf/10.1145/3214303
