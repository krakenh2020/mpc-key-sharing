# Playground for MPC-based Data Exchanges

As part of the [KRAKEN](https://krakenh2020.eu/) datamarket, users should be able to exchange data
with each other.  Since the datamarket offers analytics on data via MPC, one of the goals was to
design the data exchange also with the already present MPC setup in mind. Therefore, we designed a
data exchange platform that offers several features:

* Data exchange is possible even if the data owner is offline. Therefore, the data owner is able to
  define access policies that are checked by the datamarket and the MPC nodes. If the receiver
  satisfies the outlined requirements, they are granted access.
* The exchanged data should be end-to-end secure as long as an MPC-style assumption holds, i.e., not
  all MPC nodes have been compromised.

We follow the KEM/DEM priinciple, hence it suffices to solve the exchange of the symmetric
encryption/AEAD keys. This repoistory is therfore dedicated to prototyping some protocols that
achieve the above features.

## Dependencies

This playground requires the following dependencies to successfully run:
* `Python >= 3.7`
* `python-relic >= 0.2.1`

## Quick installation guide

If you are running Ubuntu 20.04, the easiest way to install `python-relic` is via my
[PPA](https://launchpad.net/~s-ramacher/+archive/ubuntu/ait):
```sh
sudo add-apt-repository -u ppa:s-ramacher/ait
sudo apt install python3-pyrelic
```
It comes with a pre-built version of `relic` configured for the pairing-friendly BLS12-381 curve.

Otherwise, `python-relic` can be installed via `pip`:
```sh
pip install python-relic
```

## License

The code is licensed under the MIT license and was written by Sebastian Ramacher (AIT Austrian
Institute of Technology).

## Acknowledgements

This work has been funded by the European Union’s Horizon 2020 research and innovation
programme under grant agreement No 871473 ([KRAKEN](https://krakenh2020.eu/)).
