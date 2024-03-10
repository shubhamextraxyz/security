// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

contract Test{

    function test(uint _num) external returns(bytes memory){
        return  keccak256(bytes32(_num));
    } 
}