// Block Timestamp Manipulation
// Vulnerability
// block.timestamp can be manipulated by miners with the following constraints

// it cannot be stamped with an earlier time than its parent
// it cannot be too far in the future

// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

/*
Roulette is a game where you can win all of the Ether in the contract
if you can submit a transaction at a specific timing.
A player needs to send 10 Ether and wins if the block.timestamp % 15 == 0.
*/

/*
1. Deploy Roulette with 10 Ether
2. Eve runs a powerful miner that can manipulate the block timestamp.
3. Eve sets the block.timestamp to a number in the future that is divisible by
   15 and finds the target block hash.
4. Eve's block is successfully included into the chain, Eve wins the
   Roulette game.
*/
// ###########################################
// If there is necessaty to use block.timestamp
// then rely on 15 second rule, it states that if the block.timestamp use the scale of 15 seconds or more then use it's
// generally safe to use block.timestamp for the entropy or randomness parameter.
contract Roulette {
    uint public pastBlockTime;

    constructor() payable {}

    function spin() external payable {
        require(msg.value == 10 ether); // must send 10 ether to play
        require(block.timestamp != pastBlockTime); // only 1 transaction per block

        pastBlockTime = block.timestamp;

        if (block.timestamp % 15 == 0) {
            (bool sent, ) = msg.sender.call{value: address(this).balance}("");
            require(sent, "Failed to send Ether");
        }
    }
}
// Preventative Techniques
// Don't use block.timestamp for a source of entropy and random number