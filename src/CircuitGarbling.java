import java.util.Arrays;
import java.util.logging.Logger;

public class CircuitGarbling {

    private static final Logger LOG = Logger.getLogger(CircuitGarbling.class.getSimpleName());
    /**
     * Array to store the left side of keys of the circuit participants.
     */
    private final int[] keysL = new int[2];
    /**
     * Array to store the right side of keys of the circuit participants.
     */
    private final int[] keysR = new int[2];
    /**
     * Array to store the output keys of the circuit.
     */
    private final int[] keysO = new int[2];
    /**
     * Field to store the encrypted keys.
     */
    private final int[] gt = new int[4];

    public static void main(String[] args) {
        final CircuitGarbling circuitGarbling = new CircuitGarbling();
        //circuitGarbling.garbleClassic(0);
        //circuitGarbling.garbleGRR3(0);
        circuitGarbling.garblePnP(0);
    }

    /**
     * Function that implements point and permute in combination with garbled row reduction.
     *
     * @param gateIndex index of the gate.
     * @see <a href="http://web.cs.ucdavis.edu/~rogaway/papers/bmr90">The Round Complexity of Secure Protocols</a>
     */
    private void garblePnP(int gateIndex) {
        print("=========PnP========");
        print("AND gate with id= " + gateIndex+"\n");
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = 0;
        keysO[0] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        keysO[1] = hashInsecure(2);
        int[] orderedKeys = orderCanonicalByLsb();
        print(Arrays.toString(orderedKeys));
        // Printing calculated keys
        print("\nKeys_L[0, 1] = " + Arrays.toString(keysL)
                + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        gt[1] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        // Printing encrypted keys
        print("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gt));
        print("=====================");
    }

    /**
     * Orders the keys {@link #keysL} and {@link #keysR} in an array by their LSB.<br>
     * The array will be [EVEN, EVEN, ODD, ODD].<br>
     * This fails if a key pair is not on the one side even (e.g. keyL⁰) and on the other side odd (e.g. keyL¹).
     *
     * @return ordered int array.
     */
    private int[] orderCanonicalByLsb() {
        final int[] orderedKeys = new int[4];
        assert (keysL[0] % 2 == 0 && keysL[1] % 2 == 1) || (keysL[0] % 2 == 1 && keysL[1] % 2 == 0);
        assert (keysR[0] % 2 == 0 || keysR[1] % 2 == 1) || (keysR[0] % 2 == 1 || keysR[1] % 2 == 0);
        if (keysL[0] % 2 == 0) {
            if (keysR[0] % 2 == 0) {
                setOrderByKeys(orderedKeys, keysL[0], keysR[0], keysL[1], keysR[1]);
            } else {
                setOrderByKeys(orderedKeys, keysL[0], keysR[1], keysL[1], keysR[0]);
            }
        } else { // keysL[0] is odd
            if (keysR[0] % 2 == 0) {
                setOrderByKeys(orderedKeys, keysL[1], keysR[0], keysL[0], keysR[1]);
            } else {
                setOrderByKeys(orderedKeys, keysL[1], keysR[1], keysL[0], keysR[0]);
            }
        }
        return orderedKeys;
    }

    /**
     * Helper which sets the array's indices by the given integers.
     *
     * @param orderedKeys array to set.
     * @param i           int for the first index.
     * @param i1          int for the second index.
     * @param i2          int for the third index.
     * @param i3          int for the fourth index.
     */
    private void setOrderByKeys(int[] orderedKeys, int i, int i1, int i2, int i3) {
        orderedKeys[0] = i;
        orderedKeys[1] = i1;
        orderedKeys[2] = i2;
        orderedKeys[3] = i3;
    }

    /**
     * Function that implements Garbled Row Reduction.
     *
     * @param gateIndex index of the gate.
     * @see <a href="https://dl.acm.org/citation.cfm?id=337028">Privacy preserving auctions and mechanism design</a>
     */
    private void garbleGRR3(int gateIndex) {
        LOG.info("=========GRR3========");
        LOG.info("AND gate with id= " + gateIndex);
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = 0;
        keysO[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        keysO[1] = hashInsecure(2);
        // Print calculated keys
        LOG.info("\nKeys_L[0, 1] = " + Arrays.toString(keysL)
                + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        // Print encrypted keys
        LOG.info("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gt));
        LOG.info("=====================");
    }

    /**
     * Function that garbles a single AND gate, given keyL⁰, keyL¹, keyR⁰, keyR¹ and gate index.
     * The function outputs two random keys keyO⁰, keyO¹ and a canonical sorted
     * (keyL⁰ keyR⁰, keyL⁰ keyR¹, keyL¹ keyR⁰, keyL¹ keyR¹) garbled table.
     *
     * @param gateIndex index of the gate.
     */
    private void garbleClassic(int gateIndex) {
        LOG.info("=======CLASSIC=======");
        LOG.info("AND gate with id= " + gateIndex);
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = 0;
        keysO[1] = hashInsecure(2);
        // Print calculated keys
        LOG.info("\nKeys_L[0, 1] = " + Arrays.toString(keysL)
                + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        LOG.info("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gt));
        LOG.info("=====================");
    }

    /**
     * Equivalent to E(keyO) from the exercise sheet. Encrypts the given output key by an insecure function.
     *
     * @param keyL      left key.
     * @param keyR      right key.
     * @param keyO      output key.
     * @param gateIndex index of the gate.
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

    /**
     * Helper to avoid rewriting the syso.
     *
     * @param s string to print.
     */
    private void print(String s) {
        System.out.println(s);
    }
}
