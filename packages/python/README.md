# x402-hpke (Python)

```python
from x402_hpke import create_hpke
hpke = create_hpke(namespace="myapp")
public_jwk, private_jwk = (None, None)  # use keys.generate_keypair()
```