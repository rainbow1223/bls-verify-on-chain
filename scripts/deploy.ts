import { ethers } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await ethers.provider.getBalance(deployer.address)).toString());

  // Deploy BLS Verifier
  const BLSVerifyFactory = await ethers.getContractFactory("BLSVerifyWithHashToCurve");
  const blsVerifier = await BLSVerifyFactory.deploy();

  await blsVerifier.waitForDeployment();

  const address = await blsVerifier.getAddress();
  console.log("BLS Verifier deployed to:", address);

  // Save deployment info
  console.log("\nDeployment complete!");
  console.log("Contract address:", address);
  console.log("\nTo use in tests, set CONTRACT_ADDRESS environment variable:");
  console.log(`export CONTRACT_ADDRESS=${address}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

