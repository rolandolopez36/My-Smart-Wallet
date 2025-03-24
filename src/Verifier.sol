// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {IERC1271} from "src/IERC1271.sol";

/**
 * @title Verifier
 * @dev Contract that demonstrates calling isValidSignature on an external contract (which implements ERC-1271).
 */
contract Verifier {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    /**
     * @notice Calls an ERC-1271 contract to verify a signature.
     * @param _contractAddress The address of the contract implementing IERC1271
     * @param _hash The hash of the signed data
     * @param _signature The signature bytes (r, s, v)
     */
    function callIsValidSignature(
        address _contractAddress,
        bytes32 _hash,
        bytes calldata _signature
    ) external view returns (bool) {
        bytes4 result = IERC1271(_contractAddress).isValidSignature(
            _hash,
            _signature
        );
        // Returns true if the result matches the ERC-1271 magic value
        return (result == MAGICVALUE);
    }
}
