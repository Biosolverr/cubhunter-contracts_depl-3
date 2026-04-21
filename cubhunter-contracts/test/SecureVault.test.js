const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("SecureVault", function () {
  let vault;
  let owner, guardian, counterparty, otherAccount;
  let secret, commitmentHash, lockDuration;

  const QUARANTINE_STAKE = ethers.parseEther("0.01");

  beforeEach(async function () {
    [owner, guardian, counterparty, otherAccount] = await ethers.getSigners();
    
    secret = ethers.encodeBytes32String("test-secret");
    commitmentHash = ethers.keccak256(ethers.solidityPacked(["bytes32"], [secret]));
    lockDuration = 3600; // 1 hour

    const SecureVault = await ethers.getContractFactory("SecureVault");
    vault = await upgrades.deployProxy(SecureVault, [
        owner.address,
        guardian.address,
        counterparty.address,
        commitmentHash,
        lockDuration
    ], { kind: 'uups' });
  });

  describe("Initial State", function () {
    it("1. Should set the correct initial state", async function () {
      expect(await vault.currentState()).to.equal(0); // State.INIT
    });

    it("2. Should set the correct owner and guardian roles", async function () {
      expect(await vault.owner()).to.equal(owner.address);
      const GUARDIAN_ROLE = ethers.keccak256(ethers.toUtf8Bytes("GUARDIAN_ROLE"));
      expect(await vault.hasRole(GUARDIAN_ROLE, guardian.address)).to.be.true;
    });

    it("3. Should prevent double initialization", async function () {
      await expect(vault.initialize(
        owner.address, guardian.address, counterparty.address, commitmentHash, lockDuration
      )).to.be.revertedWithCustomError(vault, "InvalidInitialization");
    });
  });

  describe("Deposits and Locking", function () {
    it("4. Should allow ETH deposit and transition to FUNDED", async function () {
      const depositAmount = ethers.parseEther("1.0");
      await expect(vault.deposit({ value: depositAmount }))
        .to.emit(vault, "Deposited")
        .withArgs(owner.address, depositAmount);
      
      expect(await vault.currentState()).to.equal(1); // State.FUNDED
      expect(await ethers.provider.getBalance(await vault.getAddress())).to.equal(depositAmount);
    });

    it("5. Should transition to LOCKED from FUNDED", async function () {
      await vault.deposit({ value: ethers.parseEther("1.0") });
      await vault.lock();
      expect(await vault.currentState()).to.equal(2); // State.LOCKED
    });

    it("6. Should prevent non-owner from locking", async function () {
      await vault.deposit({ value: ethers.parseEther("1.0") });
      await expect(vault.connect(otherAccount).lock()).to.be.revertedWithCustomError(vault, "OwnableUnauthorizedAccount");
    });
  });

  describe("Execution Logic", function () {
    beforeEach(async function () {
      await vault.deposit({ value: ethers.parseEther("1.0") });
      await vault.lock();
    });

    it("7. Should transition to EXECUTION_PENDING with correct secret", async function () {
      await time.increase(lockDuration);
      await expect(vault.initiateExecution(secret))
        .to.emit(vault, "SecretRevealed")
        .withArgs(secret);
      expect(await vault.currentState()).to.equal(3); // State.EXECUTION_PENDING
    });

    it("8. Should revert execution before lock duration expires", async function () {
      await expect(vault.initiateExecution(secret)).to.be.revertedWith("Lock period not over");
    });

    it("9. Should revert execution with wrong secret", async function () {
      await time.increase(lockDuration);
      const wrongSecret = ethers.encodeBytes32String("wrong");
      await expect(vault.initiateExecution(wrongSecret)).to.be.revertedWith("Invalid secret");
    });

    it("10. Should allow owner/counterparty to execute and transfer funds", async function () {
      await time.increase(lockDuration);
      await vault.initiateExecution(secret);
      
      const vaultBalanceBefore = await ethers.provider.getBalance(await vault.getAddress());
      expect(vaultBalanceBefore).to.equal(ethers.parseEther("1.0"));

      await vault.connect(counterparty).execute();
      
      expect(await vault.currentState()).to.equal(4); // State.EXECUTED
      expect(await ethers.provider.getBalance(await vault.getAddress())).to.equal(0);
    });
  });

  describe("Refund and Delay", function () {
    it("11. Should allow refund after lock and delay period", async function () {
      await vault.deposit({ value: ethers.parseEther("1.0") });
      await vault.lock();
      
      const refundDelay = 24 * 60 * 60; // 24h
      await time.increase(lockDuration + refundDelay + 1);
      
      const balanceBefore = await ethers.provider.getBalance(owner.address);
      await vault.refund();
      const balanceAfter = await ethers.provider.getBalance(owner.address);
      
      // Note: check approx balance due to gas
      expect(balanceAfter).to.be.closeTo(balanceBefore + ethers.parseEther("1.0"), ethers.parseEther("0.01"));
      expect(await vault.currentState()).to.equal(5); // State.REFUNDED
    });

    it("12. Should revert unauthorized refund", async function () {
      await vault.deposit({ value: ethers.parseEther("1.0") });
      await expect(vault.connect(otherAccount).refund()).to.be.revertedWith("Only owner");
    });
  });

  describe("Quarantine and Attack Simulations", function () {
    it("13. Should allow quarantine with stake", async function () {
      await expect(vault.connect(otherAccount).initiateQuarantine({ value: QUARANTINE_STAKE }))
        .to.emit(vault, "Quarantined");
      
      expect(await vault.quarantineInitiator()).to.equal(otherAccount.address);
      expect(await vault.quarantineEndTime()).to.be.gt(await time.latest());
    });

    it("14. Should revert quarantine with wrong stake amount", async function () {
      await expect(vault.connect(otherAccount).initiateQuarantine({ value: ethers.parseEther("0.001") }))
        .to.be.revertedWith("Must stake 0.01 ETH");
    });

    it("15. Attack: Direct ETH send should trigger fallback quarantine", async function () {
      await otherAccount.sendTransaction({
        to: await vault.getAddress(),
        value: QUARANTINE_STAKE
      });
      expect(await vault.quarantineInitiator()).to.equal(otherAccount.address);
    });

    it("16. Invariant Check: Balance should be zero after execute", async function () {
        await vault.deposit({ value: ethers.parseEther("1.0") });
        await vault.lock();
        await time.increase(lockDuration);
        await vault.initiateExecution(secret);
        await vault.execute();
        
        // This implicitly tests assertFundIntegrity logic through the contract call
        await vault.assertFundIntegrity();
        expect(await ethers.provider.getBalance(await vault.getAddress())).to.equal(0);
    });
  });
});
