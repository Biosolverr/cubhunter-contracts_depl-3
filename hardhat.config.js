require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: {
    compilers: [
      {
        version: "0.8.28",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          evmVersion: "cancun"
        }
      }
    ],
    overrides: {
      "contracts/SecureVault.sol": {
        version: "0.8.24",
        settings: {
          optimizer: { enabled: true, runs: 200 },
          evmVersion: "cancun"
        }
      }
    }
  },
  networks: {
    hardhat: {},
    baseSepolia: {
      url: "https://base-sepolia-rpc.publicnode.com",
      accounts: ["0xcd413d133b5adcb3cd2abed98f74d0ea8aeef2bff03f0745cf07beff0215f972"]
    }
  }
};