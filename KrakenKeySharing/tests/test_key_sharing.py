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
import unittest

from KrakenKeySharing.key_sharing import (
    aggregate,
    decaps,
    encaps,
    node_key_gen,
    node_rekey_gen,
    params,
    user_aggkey_gen,
    user_key_gen,
)


class TestKeySharing(unittest.TestCase):
    def setUp(self) -> None:
        self.pp = params()

        self.user1 = (sk1, pk1) = user_key_gen(self.pp)
        self.user2 = (sk2, pk2) = user_key_gen(self.pp)

        # Generate four node keys
        self.node1 = node_key_gen(self.pp)
        self.node2 = node_key_gen(self.pp)
        self.node3 = node_key_gen(self.pp)
        self.node4 = node_key_gen(self.pp)

        # Compute aggregation and re-encryption keys
        self.ak = user_aggkey_gen(sk2, pk1)
        self.rk1 = node_rekey_gen(self.node1[0], pk2)
        self.rk2 = node_rekey_gen(self.node2[0], pk2)
        self.rk3 = node_rekey_gen(self.node3[0], pk2)
        self.rk4 = node_rekey_gen(self.node4[0], pk2)
        self.rk5 = node_rekey_gen(self.node4[0], pk1)

    def test_normal(self) -> None:
        nodes = (self.node1[1], self.node2[1], self.node3[1])
        k, tau, ciphertexts = encaps(self.user1[0], nodes)

        ciphertext = aggregate(self.ak, (self.rk1, self.rk2, self.rk3), ciphertexts)
        received_k = decaps(self.user2[0], ciphertext, tau, nodes)
        self.assertIsNotNone(received_k)
        self.assertEqual(received_k, k)

    def test_incorrect_decaps(self) -> None:
        nodes = (self.node1[1], self.node2[1], self.node3[1])
        k, tau, ciphertexts = encaps(self.user1[0], nodes)

        ciphertext = aggregate(self.ak, (self.rk1, self.rk2, self.rk3), ciphertexts)
        received_k = decaps(
            self.user2[0],
            ciphertext,
            tau,
            (self.node1[1], self.node2[1], self.node4[1]),
        )
        self.assertIsNone(received_k)

    def test_incorrect_aggregate(self) -> None:
        nodes = (self.node1[1], self.node2[1], self.node3[1])
        k, tau, ciphertexts = encaps(self.user1[0], nodes)

        ciphertext = aggregate(self.ak, (self.rk1, self.rk2, self.rk4), ciphertexts)
        received_k = decaps(self.user2[0], ciphertext, tau, nodes)
        self.assertIsNone(received_k)

    def test_incorrect_aggregate_2(self) -> None:
        nodes = (self.node1[1], self.node2[1], self.node3[1])
        k, tau, ciphertexts = encaps(self.user1[0], nodes)

        ciphertext = aggregate(self.ak, (self.rk1, self.rk2, self.rk5), ciphertexts)
        received_k = decaps(self.user2[0], ciphertext, tau, nodes)
        self.assertIsNone(received_k)
