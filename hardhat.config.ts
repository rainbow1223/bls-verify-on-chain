import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      viaIR: false,
      evmVersion: "paris",
    },
  },
  paths: {
    sources: "./src",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts",
  },
  networks: {
    hardhat: {
      chainId: 1337,
      // Enable EIP-2537 precompiles for BLS operations
      // Note: Hardhat doesn't support EIP-2537 precompiles by default
      // You may need to use a fork of a network that supports them
      // or use a custom Hardhat plugin
    },
  },
};

export default config;

