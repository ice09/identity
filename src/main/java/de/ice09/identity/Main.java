package de.ice09.identity;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Contract;
import org.web3j.tx.ManagedTransaction;
import org.web3j.utils.Numeric;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String... args) throws Exception {
        Web3j web3j = Web3j.build(new HttpService("http://127.0.0.1:8545"));
        log.info("Connected to Ethereum client version: " + web3j.web3ClientVersion().send().getWeb3ClientVersion());
        startIdentityProcess(web3j);
    }

    private static void startIdentityProcess(Web3j web3j) throws Exception {
        // private keys correspond to the mnemonic "candy maple cake sugar pudding cream honey rich smooth crumble sweet treat"
        String pkIdentity = "c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3";
        String pkIssuer = "ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f";
        Credentials credIdentity = Credentials.create(pkIdentity);
        Credentials credIssuer = Credentials.create(pkIssuer);

        // addresses of accounts 0 and 1
        // account 0 is the deployers account, account 1 is the external signer account for the issuer contract
        log.info("Identity address: " + credIdentity.getAddress());
        log.info("Issuer address: " + credIssuer.getAddress());

        // deploy the identity contract with account 0
        // this identity contract should receive the claim
        ClaimHolder me = ClaimHolder.deploy(web3j, credIdentity, ManagedTransaction.GAS_PRICE, Contract.GAS_LIMIT).send();
        // deploy the keyholder account, the contract of the issuer of the claim, in the sample the age verifier
        KeyHolder kh = KeyHolder.deploy(web3j, credIdentity, ManagedTransaction.GAS_PRICE, Contract.GAS_LIMIT).send();
        log.info("claimholder contract: " + me.getContractAddress());
        log.info("keyholder contract: " + kh.getContractAddress());

        // add the key to the keyholder account
        // the key will be verified by the Verifier contract
        kh.addKey(Hash.sha3(Numeric.hexStringToByteArray(credIssuer.getAddress())), BigInteger.valueOf(3l), BigInteger.valueOf(1l)).send();

        // prepare signed message which is check by the Verifier contract
        // must be signed by the external account the address of which has been stored in the keyholder account in the last addKey step
        List<byte[]> values = Arrays.asList(
                // this address is the identity contract this claim is about
                Numeric.hexStringToByteArray(me.getContractAddress()),
                Numeric.toBytesPadded(BigInteger.valueOf(3l), 32),
                new byte[0]
        );
        ByteBuffer bufferValues = ByteBuffer.allocate(values.stream().mapToInt(a -> a.length).sum());
        for (byte[] a : values) {
            bufferValues.put(a);
        }
        byte[] arrayValues = bufferValues.array();
        ByteBuffer allBytes = ByteBuffer.allocate("\u0019Ethereum Signed Message:\n32".getBytes().length + 32);
        allBytes.put("\u0019Ethereum Signed Message:\n32".getBytes());
        allBytes.put(Hash.sha3(arrayValues));
        log.info("hashed parameters: " + Numeric.toHexString(Hash.sha3(allBytes.array())));
        // allBytes has all parameters which are used to recover the signer address in the Verifier contract

        Sign.SignatureData signature = Sign.signMessage(allBytes.array(), credIssuer.getEcKeyPair());
        ByteBuffer sigBuffer = ByteBuffer.allocate(signature.getR().length + signature.getS().length + 1);
        sigBuffer.put(signature.getR());
        sigBuffer.put(signature.getS());
        sigBuffer.put(signature.getV());
        log.info("signature: " + Numeric.toHexString(sigBuffer.array()));

        // finally, add the claim to the identity contract
        me.addClaim(BigInteger.valueOf(3l), BigInteger.valueOf(1l), kh.getContractAddress(), sigBuffer.array(), new byte[0], "").send();

        // deploy the Verifier contract which is bound to the keyholder contract
        ClaimVerifier verifier = ClaimVerifier.deploy(web3j, credIdentity, ManagedTransaction.GAS_PRICE, Contract.GAS_LIMIT, kh.getContractAddress()).send();

        log.info("recovered signature address: " + verifier.signedAndHashed(me.getContractAddress(), BigInteger.valueOf(3l), new byte[0], sigBuffer.array()).send());
        log.info("is claim valid? " + verifier.claimIsValid(me.getContractAddress(), BigInteger.valueOf(3l)).send());
    }
}
