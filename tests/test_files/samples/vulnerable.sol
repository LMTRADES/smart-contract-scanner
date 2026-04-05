// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @dev Contains multiple intentional vulnerabilities for testing the scanner
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    // VULNERABILITY: Reentrancy - external call before state update
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0;
    }

    // VULNERABILITY: tx.origin authorization
    function transferOwnership(address newOwner) public {
        require(tx.origin == owner());
        _setOwner(newOwner);
    }

    function owner() public view returns (address) {
        return address(0x1);
    }

    function _setOwner(address newOwner) internal {}

    // VULNERABILITY: Unchecked low-level call
    function sendTo(address recipient, uint256 amount) public {
        address(recipient).call{value: amount}("");
    }

    // VULNERABILITY: Delegatecall to user-controlled address
    function doDelegatecall(address target, bytes memory data) public {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }

    // VULNERABILITY: Selfdestruct without access control
    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    // VULNERABILITY: Using block.timestamp for time lock
    function timedWithdraw() public {
        require(block.timestamp > 1700000000);
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(bal);
    }

    // VULNERABILITY: Hardcoded address/secrets
    function useHardcoded() public {
        address secretWallet = 0xDeadBeef1234567890123456789012345678;
        payable(secretWallet).transfer(address(this).balance);
    }

    // VULNERABILITY: Weak randomness using blockhash
    function lottery() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 100;
    }

    // VULNERABILITY: Missing zero address check
    function setCriticalAddress(address criticalAddress) public {
        criticalAddress; // Just assign without checking for zero
    }

    // VULNERABILITY: Missing visibility modifier
    function internalHelper() {
        // Should be explicitly marked
    }

    // VULNERABILITY: Integer arithmetic (flagged by pattern though 0.8+ is safe)
    function calculateReward(uint256 amount, uint256 multiplier) public pure returns (uint256) {
        return amount * multiplier + 100;
    }
}
