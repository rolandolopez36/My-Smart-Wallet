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
        // Generate a keccak256 hash from the message to sign
        bytes32 hash = keccak256(abi.encodePacked("Message to sign"));

        // Sign the hash using the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivateKey, hash);

        // Combine the signature parts (r, s, v) into a single bytes array
        bytes memory signature = abi.encodePacked(r, s, v);

        // Perform a static call to the wallet contract's isValidSignature function
        (bool success, bytes memory returnData) = address(wallet).staticcall(
            abi.encodeWithSelector(
                wallet.isValidSignature.selector,
                hash,
                signature
            )
        );

        // Log debugging information for the hash, signature, call success, and return data
        emit log_named_bytes32("Hash", hash);
        emit log_named_bytes("Signature", signature);
        emit log_named_string("Success", success ? "true" : "false");
        emit log_named_bytes("Return Data", returnData);

        // Ensure the call did not revert
        assertTrue(success, "The call to isValidSignature failed");

        // Decode the returned bytes into bytes4 and compare it to the expected magic value.
        // Since there's no assert for bytes4, we convert to uint32 for comparison.
        bytes4 result = abi.decode(returnData, (bytes4));
        assertEq(
            uint32(result),
            uint32(0x1626ba7e),
            "isValidSignature did not return the expected magic value"
        );
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
