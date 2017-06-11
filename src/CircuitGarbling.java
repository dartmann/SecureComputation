import java.util.Arrays;
import java.util.logging.Logger;

public class CircuitGarbling {

    private static final Logger LOG = Logger.getLogger(CircuitGarbling.class.getSimpleName());

    public static void main(String[] args) {
        final CircuitGarbling circuitGarbling = new CircuitGarbling();
        //circuitGarbling.garbleClassic(0);
        circuitGarbling.garbleGRR3(0);
    }

    /**
     * Function that implements Garbled Row Reduction.
     * @see <a href="https://dl.acm.org/citation.cfm?id=337028">Privacy preserving auctions and mechanism design</a>
     */
    private void garbleGRR3(int gateIndex) {
        LOG.info("=========GRR3========");
        LOG.info("AND gate with id= " + gateIndex);
        /*
        Fields to use for storing the keys
         */
        final int[] keysL = new int[2];
        final int[] keysR = new int[2];
        final int[] keysO = new int[2];
        /*
        Field to store the encrypted values
         */
        final int[] gt = new int[4];
        /*
        Calculating the keys
         */
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = 0;
        keysO[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        keysO[1] = hashInsecure(2);
        /*
        Printing calculated keys
         */
        LOG.info("\nKeys_L[0, 1] = " + Arrays.toString(keysL)
                + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        /*
        Encrypt the four values of the AND gate
         */
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        /*
        Printing encrypted keys
         */
        LOG.info("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gt));
        LOG.info("=====================");
    }

    /**
     * Function that garbles a single AND gate, given keyL⁰, keyL¹, keyR⁰, keyR¹ and gate index.
     * The function outputs two random keys keyO⁰, keyO¹ and a canonical sorted
     * (keyL⁰ keyR⁰, keyL⁰ keyR¹, keyL¹ keyR⁰, keyL¹ keyR¹) garbled table.
     */
    private void garbleClassic(int gateIndex) {
        LOG.info("=======CLASSIC=======");
        LOG.info("AND gate with id= " + gateIndex);
        /*
        Fields to use for storing the keys
         */
        final int[] keysL = new int[2];
        final int[] keysR = new int[2];
        final int[] keysO = new int[2];
        /*
        Field to store the encrypted values
         */
        final int[] gt = new int[4];
        /*
        Calculating the keys
         */
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = 0;
        keysO[1] = hashInsecure(2);

        LOG.info("\nKeys_L[0, 1] = " + Arrays.toString(keysL)
                + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        /*
        Encrypt the four values of the AND gate
         */
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        LOG.info("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gt));
        LOG.info("=====================");
    }

    /**
     * Equivalent to E(k_O) from the exercise sheet. Encrypts the given output key by an insecure function.
     *
     * @param keyL left key.
     * @param keyR right key.
     * @param keyO output key.
     * @return computed value.
     */
    private int encryptInsecure(int keyL, int keyR, int keyO, int gateIndex) {
        return hashInsecure(keyL ^ (keyR << 1) ^ gateIndex) ^ keyO;
    }

    /**
     * Equivalent to H(x) from the exercise sheet. Hashes the given int by an insecure function.
     *
     * @param x desired value to hash.
     * @return computed hash.
     */
    private int hashInsecure(int x) {
        return ((x + 17) * 11047) % 65521;
    }
}
