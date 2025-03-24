// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title ERC-1271: Standard Signature Validation Method for Contracts
 * @dev Interface according to the EIP-1271 specification for contracts that validate signatures.
 */
interface IERC1271 {
    /**
     * @dev Must return 0x1626ba7e when the signature is valid for the given hash.
     *      Must return 0xffffffff when the signature is invalid.
     */
    function isValidSignature(
        bytes32 _hash,
        bytes calldata _signature
    ) external view returns (bytes4 magicValue);
}
