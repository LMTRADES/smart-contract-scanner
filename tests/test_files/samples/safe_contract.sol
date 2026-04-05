// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/**
 * @title SafeBank
 * @dev Example of a properly secured contract with no vulnerabilities
 */

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SafeBank is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    // SAFE: Checks-Effects-Interactions + ReentrancyGuard
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        require(amount > 0, "Amount must be greater than 0");
        balances[msg.sender] -= amount;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Withdrawal failed");
        emit Withdrawal(msg.sender, amount);
    }

    // SAFE: Proper access control with msg.sender (not tx.origin)
    function emergencyWithdraw() external onlyOwner {
        uint256 bal = address(this).balance;
        payable(owner()).transfer(bal);
    }

    // SAFE: Safe math (0.8.19 has built-in overflow protection)
    function calculateFee(uint256 amount) public pure returns (uint256) {
        return (amount * 5) / 100;
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }
}
