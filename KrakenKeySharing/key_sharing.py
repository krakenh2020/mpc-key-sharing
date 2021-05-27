# Copyright 2021 Sebastian Ramacher <sebastian.ramacher@ait.ac.at>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Experiments for MPC-style key sharing in an non-interactive fashion.
"""
import os
import enum
import struct
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Iterable,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import pyrelic
from pyrelic import (
    BN,
    neutral_BN,
    G1,
    G2,
    GT,
    generator_G1,
    generator_G2,
    hash_to_G1,
    mul_sim_G1,
    neutral_GT,
    pair,
    pair_product,
    rand_BN_order,
    rand_G1,
)

T = TypeVar("T")


def _prod(values: Iterable[GT], start: Optional[GT] = None) -> GT:
    """math.prod from Python 3.8+ for GT elements"""

    result = start if start is not None else neutral_GT()
    for value in values:
        result *= value
    return result


# The HPRA and HPRE implementations are based on examples/hpra.py from python-relic
# which is licensed under the MIT license and copyright 2021 Sebastian Ramacher
# <sebastian.ramacher@ait.ac.at>


@dataclass
class HPRAParams:
    """Public parameters for HPRA."""

    length: int
    gs: Tuple[G1, ...]


def _hpra_params(length: int) -> HPRAParams:
    """Generate public parameters for HPRA."""

    return HPRAParams(
        length,
        tuple(
            hash_to_G1(b" ".join((b"public params", struct.pack("<L", i))))
            for i in range(length)
        ),
    )


@dataclass
class HPRASPublicKey:
    pk1: G2
    pk2: G2
    pp: HPRAParams


@dataclass
class HPRASPrivateKey:
    beta: BN
    pk: HPRASPublicKey
    pp: HPRAParams = field(init=False)

    def __post_init__(self) -> None:
        self.pp = self.pk.pp


@dataclass
class _HPRAVMK:
    alpha: BN
    pp: HPRAParams


@dataclass
class HPRAAK:
    ak: G2


def _hpra_sgen(pp: HPRAParams) -> Tuple[HPRASPrivateKey, HPRASPublicKey]:
    beta = rand_BN_order()
    g2beta = generator_G2(beta)
    g2betainv = generator_G2(beta.mod_inv(pyrelic.order()))

    pk = HPRASPublicKey(g2beta, g2betainv, pp)
    return HPRASPrivateKey(beta, pk), pk


def _hpra_hash(*args: Any) -> G1:
    return hash_to_G1(b"|".join(bytes(arg) for arg in args))


def _hpra_vgen(pp: HPRAParams) -> Tuple[_HPRAVMK, None]:
    alpha = rand_BN_order()
    return _HPRAVMK(alpha, pp), None


def _hpra_sign(sk: HPRASPrivateKey, messages: Sequence[BN], tau: Any, id_=None) -> G1:
    sigma = _hpra_hash(tau, id_ if id_ is not None else sk.pk.pk1)
    sigma = mul_sim_G1(sk.pk.pp.gs, messages, sigma)
    return sigma ** sk.beta


def _hpra_vrgen(pk: HPRASPublicKey, mk: _HPRAVMK) -> HPRAAK:
    ak = pk.pk2 ** mk.alpha
    return HPRAAK(ak)


def _hpra_agg(
    aks: Sequence[HPRAAK],
    sigmas: Sequence[G1],
    messages: Sequence[T],
    evalf: Callable[[Sequence[T]], T],
) -> Tuple[T, GT]:
    msg = evalf(messages)
    mu = pair_product(*((sigma, ak.ak) for sigma, ak in zip(sigmas, aks)))
    return msg, mu


@dataclass
class HPREPrivateKey:
    a1: Tuple[BN, ...]
    a2: Tuple[BN, ...]


@dataclass
class HPREPublicKey:
    pk1: Tuple[GT, ...]
    pk2: Tuple[G2, ...]

    def __post_init__(self):
        assert len(self.pk1) == len(self.pk2)

    def __bytes__(self) -> bytes:
        return b"||".join(
            (
                b"|".join(bytes(x) for x in self.pk1),
                b"|".join(bytes(x) for x in self.pk2),
            )
        )


def _hpre_keygen(length: int) -> Tuple[HPREPrivateKey, HPREPublicKey]:
    assert length >= 1
    a1 = tuple(rand_BN_order() for _ in range(length))
    a2 = tuple(rand_BN_order() for _ in range(length))

    sk = HPREPrivateKey(a1, a2)
    pk = HPREPublicKey(
        tuple(pair(generator_G1(a), generator_G2()) for a in a1),
        tuple(generator_G2(a) for a in a2),
    )

    return sk, pk


@dataclass
class HPREReEncKey:
    rk: Tuple[G2, ...]


def _hpre_rg(sk: HPREPrivateKey, pk: HPREPublicKey) -> HPREReEncKey:
    return HPREReEncKey(tuple(pk2 ** a1 for pk2, a1 in zip(pk.pk2, sk.a1)))


class _HPRECiphertextLevel(enum.Enum):
    L2 = enum.auto()
    LR = enum.auto()


@dataclass
class HPRECiphertext:
    level: _HPRECiphertextLevel
    c0: Union[G1, Tuple[GT, ...]]
    cs: Tuple[GT, ...]


def _hpre_encrypt(
    pk: HPREPublicKey,
    messages: Sequence[GT],
) -> HPRECiphertext:
    k = rand_BN_order()
    cs = tuple(m * pk1 ** k for m, pk1 in zip(messages, pk.pk1))
    return HPRECiphertext(_HPRECiphertextLevel.L2, generator_G1(k), cs)


def _hpre_rencrypt(rk: HPREReEncKey, ciphertext: HPRECiphertext) -> HPRECiphertext:
    assert ciphertext.level == _HPRECiphertextLevel.L2
    return HPRECiphertext(
        _HPRECiphertextLevel.LR,
        tuple(pair(cast(G1, ciphertext.c0), r) for r in rk.rk),
        ciphertext.cs,
    )


def _hpre_decrypt(sk: HPREPrivateKey, ciphertext: HPRECiphertext) -> Tuple[GT, ...]:
    assert ciphertext.level == _HPRECiphertextLevel.LR

    order = pyrelic.order()
    return tuple(
        c1 / c0 ** a2.mod_inv(order)
        for c0, c1, a2 in zip(cast(Sequence[GT], ciphertext.c0), ciphertext.cs, sk.a2)
    )


def params() -> HPRAParams:
    """Generate public parameters."""

    return _hpra_params(1)


@dataclass
class UserPrivateKey:
    """User's private key."""

    sk: HPRASPrivateKey
    vk: _HPRAVMK
    rsk: HPREPrivateKey
    rpk: HPREPublicKey
    pp: HPRAParams = field(init=False)

    def __post_init__(self):
        self.pp = self.sk.pk.pp


@dataclass
class UserPublicKey:
    """User's public key."""

    pk: HPRASPublicKey
    rpk: HPREPublicKey


def user_key_gen(pp: HPRAParams) -> Tuple[UserPrivateKey, UserPublicKey]:
    """Generate key pair for a user."""

    sk, pk = _hpra_sgen(pp)
    vk, _ = _hpra_vgen(pp)
    rsk, rpk = _hpre_keygen(pp.length + 1)

    return UserPrivateKey(sk, vk, rsk, rpk), UserPublicKey(pk, rpk)


def node_key_gen(pp: HPRAParams) -> Tuple[HPREPrivateKey, HPREPublicKey]:
    """Generate key pair for a node."""

    return _hpre_keygen(pp.length + 1)


@dataclass
class Ciphertext:
    sigma: G1
    c: HPRECiphertext


def encaps(
    sk: UserPrivateKey, nodes: Sequence[HPREPublicKey]
) -> Tuple[GT, bytes, Tuple[Ciphertext, ...]]:
    """Encaps a freshly sampled key shared with respect to the given nodes.

    Returns the key, the tag tau and the ciphertexts.
    """

    num_nodes = len(nodes)
    assert num_nodes >= 3

    pp = sk.pp
    tau = os.urandom(32)
    # Produce random shares
    ks = [rand_BN_order() for _ in range(num_nodes)]

    rs = tuple(rand_G1() for _ in range(num_nodes))
    g2 = generator_G2()
    # Produce signatures
    sigmas = (
        _hpra_sign(sk.sk, (ki,), tau, bytes(node)) * r
        for ki, r, node in zip(ks, rs, nodes)
    )
    # Produce ciphertexts
    cs = (
        _hpre_encrypt(
            node,
            tuple(
                pair(lhs, rhs)
                for lhs, rhs in (
                    (pp.gs[0] ** ki, g2),
                    (ri, sk.sk.pk.pk2),
                )
            ),
        )
        for ki, ri, node in zip(ks, rs, nodes)
    )

    return (
        pair(pp.gs[0] ** (sum(ks, neutral_BN()) % pyrelic.order()), generator_G2()),
        tau,
        tuple(Ciphertext(sigma, c) for sigma, c in zip(sigmas, cs)),
    )


def user_aggkey_gen(sk: UserPrivateKey, pk: UserPublicKey) -> HPRAAK:
    """Computes aggregation key for ciphertexts transformed from sk to pk."""

    return _hpra_vrgen(pk.pk, sk.vk)


def node_rekey_gen(sk: HPREPrivateKey, pk: UserPublicKey) -> HPREReEncKey:
    """Generate reencryption key from MPC node to pk."""

    return _hpre_rg(sk, pk.rpk)


@dataclass
class AggCiphertext:
    """Aggregated ciphertext."""

    c: HPRECiphertext
    mu: GT

    def __post_init__(self) -> None:
        assert self.c.level == _HPRECiphertextLevel.LR


def aggregate(
    ak: HPRAAK, rks: Sequence[HPREReEncKey], ciphertexts: Sequence[Ciphertext]
) -> AggCiphertext:
    """Aggregate and reencrypt ciphertexts."""

    def evalcs(cs: Sequence[HPRECiphertext]) -> HPRECiphertext:
        length = len(cs[0].cs)
        return HPRECiphertext(
            cs[0].level,
            tuple(
                _prod((cast(Sequence[GT], c.c0)[idx] for c in cs))
                for idx in range(length)
            ),
            tuple(_prod((cast(GT, c.cs[idx]) for c in cs)) for idx in range(length)),
        )

    return AggCiphertext(
        *_hpra_agg(
            [ak] * len(rks),
            tuple(ciphertext.sigma for ciphertext in ciphertexts),
            tuple(
                _hpre_rencrypt(rk, ciphertext.c)
                for rk, ciphertext in zip(rks, ciphertexts)
            ),
            evalcs,
        )
    )


def decaps(
    sk: UserPrivateKey,
    ciphertext: AggCiphertext,
    tau: Any,
    ids: Sequence[HPREPublicKey],
) -> Optional[GT]:
    """Verify and decaps authenticated key.

    Returns the key if verification succeeds and None otherwise.
    """

    def averify(mk: _HPRAVMK, msg: GT, mu: GT) -> bool:
        ghat = generator_G2()
        muprime = (
            msg
            * pair_product(
                *(
                    (
                        _hpra_hash(tau, node),
                        ghat,
                    )
                    for node in ids
                ),
            )
        ) ** mk.alpha
        return muprime == mu

    ms = _hpre_decrypt(sk.rsk, ciphertext.c)
    msu, r = ms[0], ms[1]
    return msu if averify(sk.vk, msu, ciphertext.mu / (r ** sk.vk.alpha)) else None
