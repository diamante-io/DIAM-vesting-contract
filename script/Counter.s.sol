// pragma solidity ^0.8.13;

// import {Script, console} from "../lib/forge-std/src/Script.sol";
// import {StringStorage} from "../src/myContract.sol";

// contract CounterScript is Script {
//     StringStorage public counter;

//     function setUp() public {}

//     function run() public {
//         vm.startBroadcast();

//         counter = new StringStorage();

//         vm.stopBroadcast();
//     }
// }

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script, console} from "../lib/forge-std/src/Script.sol";
import {DIAMVesting} from "../src/DIAMVesting.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// contract MockERC20 is ERC20 {
//     constructor() ERC20("MockToken", "MTK") {
//         _mint(address(1), 1_000_000 ether);
//     }
// }

// contract CounterScript is Script {
//     DIAMVesting public vestingContract;
//     MockERC20 public token;

//     function setUp() public {}

//     function run() public {
//         vm.startBroadcast();

//         // Deploy the mock ERC20 token
//         token = new MockERC20();
//         console.log("MockERC20 deployed at:", address(token));

//         // Deploy the DIAMVesting contract with the mock token address
//         vestingContract = new DIAMVesting(address(token));
//         console.log("DIAMVesting deployed at:", address(vestingContract));
      

//         vm.stopBroadcast();
//     }
// }

contract Deploy is Script {
    function run() external {
        // Load private key from the environment
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        // Start broadcast from your wallet
        vm.startBroadcast(privateKey);

        // Deploy the contract
        DIAMVesting contractInstance = new DIAMVesting(address(0x1FA0f5ed24a1a2b43741E88F8FEc19633e67082B));

        // Log the deployed contract address
        console.log("Deployed Contract Address:", address(contractInstance));

        // Stop broadcasting transactions
        vm.stopBroadcast();
    }
}