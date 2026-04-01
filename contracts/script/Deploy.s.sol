// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/TOPRFRegistry.sol";

contract DeployScript is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");

        vm.startBroadcast(deployerKey);
        TOPRFRegistry registry = new TOPRFRegistry();
        vm.stopBroadcast();

        console.log("TOPRFRegistry deployed at:", address(registry));
        console.log("Owner:", registry.owner());
    }
}
