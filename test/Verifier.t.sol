// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import {MySmartWallet} from "src/MySmartWallet.sol";
import {IERC1271} from "src/IERC1271.sol";

// If Verifier is defined in another file, make sure to import it.
// e.g. import {Verifier} from "src/Verifier.sol";
contract Verifier {
    bytes4 internal constant MAGICVALUE = 0x1626ba7e;

    function callIsValidSignature(
        address _contractAddress,
        bytes32 _hash,
        bytes calldata _signature
    ) external view returns (bool) {
        bytes4 result = IERC1271(_contractAddress).isValidSignature(
            _hash,
            _signature
        );
        return (result == MAGICVALUE);
    }
}

contract VerifierTest is Test {
    MySmartWallet public wallet;
    Verifier public verifier;
    address public owner;
    uint256 public ownerPrivateKey = 1; // Fixed private key for the owner

    function setUp() public {
        // Create an 'owner' address using a fixed private key
        owner = vm.addr(ownerPrivateKey);
        // Deploy the contract that implements ERC-1271
        wallet = new MySmartWallet(owner);
        // Deploy the Verifier contract
        verifier = new Verifier();
    }

    /**
     * @dev Test: Verify a valid signature using the Verifier contract
     */
    function testVerifierWithValidSignature() public {
        // Create an arbitrary hash
        bytes32 hash = keccak256(abi.encodePacked("Message to sign"));

        // Sign with 'owner' using the fixed private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, hash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // Call Verifier.callIsValidSignature(...)
        bool isValid = verifier.callIsValidSignature(
            address(wallet),
            hash,
            signature
        );
        assertTrue(isValid, "The signature should be valid");
    }

    /**
     * @dev Test: Verify an invalid signature (signed by a different account)
     */
    function testVerifierWithInvalidSignature() public {
        bytes32 hash = keccak256(abi.encodePacked("Another message"));

        // Use a different private key for notOwner
        uint256 notOwnerPrivateKey = 2;
        address notOwner = vm.addr(notOwnerPrivateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(notOwnerPrivateKey, hash);

        bytes memory signature = abi.encodePacked(r, s, v);

        // We expect it to be false (invalid signature)
        bool isValid = verifier.callIsValidSignature(
            address(wallet),
            hash,
            signature
        );
        assertFalse(isValid, "The signature should be invalid");
    }

    /**
     * @dev Fuzz test for Verifier
     */
    function testFuzz_CallIsValidSignature(
        bytes32 randomHash,
        bytes memory randomSignature
    ) public {
        bool isValid = verifier.callIsValidSignature(
            address(wallet),
            randomHash,
            randomSignature
        );
        // It will normally be 'false', but it could be 'true' if the signature aligns with 'owner'.
        // We'll log in case it's true.
        if (isValid) {
            emit log("Random signature was unexpectedly valid!");
        }
    }
}
