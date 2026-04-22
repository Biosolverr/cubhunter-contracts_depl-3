const { ethers, upgrades } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying contracts with the account:", deployer.address);

  const SecureVault = await ethers.getContractFactory("SecureVault");

  const owner = deployer.address;
  const guardian = "0x000000000000000000000000000000000000dEaD"; // замени на реальный адрес
  const counterparty = "0x000000000000000000000000000000000000bEEF"; // замени на реальный адрес
  const secret = ethers.encodeBytes32String("secret-code");
  const commitmentHash = ethers.keccak256(
    ethers.solidityPacked(["bytes32"], [secret])
  );
  const lockDuration = 60 * 60 * 24; // 24 часа

  console.log("Deploying SecureVault as UUPS proxy...");

  const vault = await upgrades.deployProxy(
    SecureVault,
    [owner, guardian, counterparty, commitmentHash, lockDuration],
    { initializer: "initialize", kind: "uups" }
  );

  await vault.waitForDeployment();
  const vaultAddress = await vault.getAddress();

  console.log("SecureVault proxy deployed to:", vaultAddress);
  console.log("-----------------------------------");
  console.log("Configured Parameters:");
  console.log("- Owner:          ", owner);
  console.log("- Guardian:       ", guardian);
  console.log("- Counterparty:   ", counterparty);
  console.log("- CommitmentHash: ", commitmentHash);
  console.log("- LockDuration:   ", lockDuration, "seconds");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
