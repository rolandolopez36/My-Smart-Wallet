# My Smart Wallet

My Smart Wallet demonstrates a simple setup for an ERC-1271 contract and related testing using Foundry. It includes:

- **`MySmartWallet.sol`**: A contract that implements the ERC-1271 interface to validate signatures.
- **`Verifier.sol`**: An example contract that calls `isValidSignature` on an ERC-1271-compatible contract.
- **Tests**: Foundry test files containing both unit tests and fuzz tests.

Feel free to add additional information or examples below!

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Gas Snapshots

```shell
$ forge snapshot
```
