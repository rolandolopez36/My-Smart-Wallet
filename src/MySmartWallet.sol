// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IERC1271} from "src/IERC1271.sol";

/**
 * @title MySmartWallet
 * @dev Example contract that implements ERC-1271 and validates signatures.
 */
contract MySmartWallet is IERC1271 {
    // Magic value defined in EIP-1271 for valid signatures
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    // Error value for invalid signatures
    bytes4 internal constant INVALIDVALUE = 0xffffffff;

    // The owner of this "smart wallet"
    address public owner;

    /**
     * @dev Sets the owner via the constructor.
     * @param _owner The address that will act as the owner of this contract.
     */
    constructor(address _owner) {
        require(_owner != address(0), "Owner cannot be zero address");
        owner = _owner;
    }

    /**
     * @notice Function implementing the EIP-1271 interface
     * @dev Must return MAGICVALUE (0x1626ba7e) when the signature is valid
     * @param _hash The hash of the data that was signed
     * @param _signature The signature in bytes
     */
    function isValidSignature(
        bytes32 _hash,
        bytes calldata _signature
    ) external view override returns (bytes4 magicValue) {
        if (recoverSigner(_hash, _signature) == owner) {
            return MAGICVALUE;
        } else {
            return INVALIDVALUE;
        }
    }

    /**
     * @dev Recovers the address that signed a hash with its private key (EOA).
     * @param _hash The hash of the signed data.
     * @param _signature The signature in bytes in the format (r, s, v).
     */
    function recoverSigner(
        bytes32 _hash,
        bytes memory _signature
    ) internal pure returns (address) {
        if (_signature.length != 65) {
            return address(0);
        }

        bytes32 r;
        bytes32 s;
        uint8 v;

        // The signature is composed of r (32 bytes), s (32 bytes), and v (1 byte)
        assembly {
            r := mload(add(_signature, 32))
            s := mload(add(_signature, 64))
            v := byte(0, mload(add(_signature, 96)))
        }

        // EIP-2 imposes that s must be less than secp256k1n ÷ 2 + 1, and v must be 27 or 28.
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return address(0);
        }

        if (v != 27 && v != 28) {
            return address(0);
        }

        // ecrecover returns address(0) on error
        address signer = ecrecover(_hash, v, r, s);
        return signer;
    }
}
