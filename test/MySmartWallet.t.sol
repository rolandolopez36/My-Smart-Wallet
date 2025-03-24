// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {MySmartWallet} from "src/MySmartWallet.sol";

/**
 * @title Unit tests and fuzzing for MySmartWallet
 */
contract MySmartWalletTest is Test {
    MySmartWallet public wallet;
    address public owner;
    uint256 public ownerPrivateKey = 1; // Fixed private key for the owner

    // Magic values
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;
    bytes4 internal constant INVALIDVALUE = 0xffffffff;

    function setUp() public {
        // Set the owner using a fixed private key
        owner = vm.addr(ownerPrivateKey);
        // Deploy the wallet with the specified owner
        wallet = new MySmartWallet(owner);
    }

    /**
     * @dev Basic unit test: verify that the owner is set correctly.
     */
    function testOwnerIsSet() public {
        assertEq(wallet.owner(), owner, "The owner does not match");
    }

    /**
     * @dev Unit test: sign a hash with the owner and check that isValidSignature returns MAGICVALUE.
     */
    function testValidSignature() public {
        // Prepare a random hash
        bytes32 hash = keccak256(abi.encodePacked("Hola ERC-1271"));

        // Sign the hash with the 'owner' account using cheatcodes
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, hash);

        // Build the signature in (r, s, v) format as bytes
        bytes memory signature = abi.encodePacked(r, s, v);

        // Call isValidSignature directly
        (bool success, bytes memory returnData) = address(wallet).staticcall(
            abi.encodeWithSelector(
                wallet.isValidSignature.selector,
                hash,
                signature
            )
        );

        assertTrue(success, "The call to isValidSignature failed");

        // Decode the returned value (bytes4)
        bytes4 result = abi.decode(returnData, (bytes4));

        // Verify that it returns the magic value
        assertEq(result, MAGICVALUE, "The signature should be valid");
    }

    /**
     * @dev Unit test: test an invalid signature (signed by a different address).
     */
    function testInvalidSignature() public {
        // Prepare a random hash
        bytes32 hash = keccak256(abi.encodePacked("Test hash"));

        // Use a different private key for notOwner
        uint256 notOwnerPrivateKey = 2;
        address notOwner = vm.addr(notOwnerPrivateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(notOwnerPrivateKey, hash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Call isValidSignature
        (bool success, bytes memory returnData) = address(wallet).staticcall(
            abi.encodeWithSelector(
                wallet.isValidSignature.selector,
                hash,
                signature
            )
        );

        assertTrue(success, "The call to isValidSignature failed");

        bytes4 result = abi.decode(returnData, (bytes4));
        // It should return 0xffffffff (invalid signature)
        assertEq(result, INVALIDVALUE, "The signature should be invalid");
    }

    /**
     * @dev Example Fuzz Test: Test with random inputs for the signature.
     */
    function testFuzz_InvalidSignature(
        bytes32 _randomHash,
        bytes memory _randomSignature
    ) public {
        // We call isValidSignature with random data.
        // It is very likely that the signature is invalid and returns INVALIDVALUE (0xffffffff).
        (bool success, bytes memory returnData) = address(wallet).staticcall(
            abi.encodeWithSelector(
                wallet.isValidSignature.selector,
                _randomHash,
                _randomSignature
            )
        );

        // We can verify that it does not revert
        assertTrue(success, "The call to isValidSignature reverted");

        // Decode the returned value
        bytes4 result = abi.decode(returnData, (bytes4));

        // In most random cases we expect INVALIDVALUE.
        // It would only be MAGICVALUE if by some chance a valid signature for 'owner' is produced.
        if (result == MAGICVALUE) {
            // This is a very rare case; if it happens, it means the random input matched the signer's signature
            emit log(
                "Found a random hash/signature combo that matches the signer!"
            );
        } else {
            assertEq(result, INVALIDVALUE, "Expected an invalid signature");
        }
    }
}
