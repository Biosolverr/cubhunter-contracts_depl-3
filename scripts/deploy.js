const hre = require("hardhat");

async function main() {
  const SecureVault = await hre.ethers.getContractFactory("SecureVault");

  console.log("Deploying SecureVault...");

  const vault = await SecureVault.deploy();

  await vault.deployed();

  console.log("SecureVault deployed to:", vault.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});