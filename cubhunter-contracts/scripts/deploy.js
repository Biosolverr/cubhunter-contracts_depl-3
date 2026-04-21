const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  // For a production UUPS project, you would normally use @openzeppelin/hardhat-upgrades
  // but here we demonstrate a base deployment and initialization as requested.
  
  const SecureVault = await ethers.getContractFactory("SecureVault");
  
  // Parameters for initialization
  const owner = deployer.address;
  const guardian = "0x000000000000000000000000000000000000dead"; // Placeholder
  const counterparty = "0x000000000000000000000000000000000000beef"; // Placeholder
  const secret = ethers.encodeBytes32String("secret-code");
  const commitmentHash = ethers.keccak256(ethers.solidityPacked(["bytes32"], [secret]));
  const lockDuration = 60 * 60 * 24; // 24 hours

  console.log("Deploying SecureVault...");
  const vault = await SecureVault.deploy();
  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();

  console.log("SecureVault deployed to:", vaultAddress);

  console.log("Initializing...");
  const initTx = await vault.initialize(
    owner,
    guardian,
    counterparty,
    commitmentHash,
    lockDuration
  );
  await initTx.wait();

  console.log("SecureVault initialized successfully.");
  console.log("-----------------------------------");
  console.log("Configured Parameters:");
  console.log("- Owner:", owner);
  console.log("- Guardian:", guardian);
  console.log("- Counterparty:", counterparty);
  console.log("- CommitmentHash:", commitmentHash);
  console.log("- LockDuration:", lockDuration, "seconds");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
