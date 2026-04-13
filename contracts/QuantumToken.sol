// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract QuantumToken is ERC20, Ownable {
    mapping(address => bytes32) public publicKeys;
    mapping(address => uint256) public nonces;

    event PublicKeyRegistered(address indexed account, bytes32 publicKey);
    event QuantumTransfer(address indexed from, address indexed to, uint256 amount);

    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply
    ) ERC20(name, symbol) Ownable(msg.sender) {
        _mint(msg.sender, initialSupply);
    }

    function transfer(address, uint256) public pure override returns (bool) {
        revert("ECDSA transfers are disabled; use quantumTransfer");
    }

    function transferFrom(address, address, uint256) public pure override returns (bool) {
        revert("ECDSA transfers are disabled; use quantumTransfer");
    }

    function registerPublicKey(bytes32 _publicKey) external {
        publicKeys[msg.sender] = _publicKey;
        emit PublicKeyRegistered(msg.sender, _publicKey);
    }

    function quantumTransfer(
        address to,
        uint256 amount,
        bytes32[] calldata signature,
        bytes32 messageHash
    ) external {
        require(publicKeys[msg.sender] != bytes32(0), "Public key not registered");
        require(to != address(0), "Invalid receiver");

        bytes32 expectedHash = keccak256(abi.encodePacked(msg.sender, to, amount, nonces[msg.sender]));
        require(messageHash == expectedHash, "Invalid message hash");

        require(_simulateQuantumVerification(publicKeys[msg.sender], messageHash, signature), "Invalid quantum signature");

        nonces[msg.sender]++;

        // Use a safe internal transfer to bypass overridden transfer behavior
        _transfer(msg.sender, to, amount);
        emit QuantumTransfer(msg.sender, to, amount);
    }

    function _simulateQuantumVerification(
        bytes32 /*publicKey*/,
        bytes32 /*message*/,
        bytes32[] memory signature
    ) internal pure returns (bool) {
        require(signature.length > 0, "Empty signature");
        return true;
    }
}
