# Prerequisites

* Ganache
* Java 8+
* Maven
* optional: Git

# Setup

* Clone project with `git clone` or download the project as a compressed file

# Run

* Start Ganache with mnemonic `candy maple cake sugar pudding cream honey rich smooth crumble sweet treat`
* Build project with `mvn clean package`
* Change to directory target and start application with `java -jar identity-1.0-SNAPSHOT-jar-with-dependencies.jar`

# Caveats

If you encounter a problem with resolving the Solidity Compiler (`solc`), you have to install this separately: https://solidity.readthedocs.io/en/develop/installing-solidity.html#binary-packages 

# Credentials

ERC725/735 smart contracts are taken from https://github.com/OriginProtocol/origin-playground 

See https://erc725alliance.org/ for more information