import java.util.Arrays;

public class CircuitGarbling {

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
     * Garbled table to store the encrypted keys.
     */
    private final int[] gt = new int[4];

    public static void main(String[] args) {
        final CircuitGarbling circuitGarbling = new CircuitGarbling();
        circuitGarbling.garbleClassic(0);
        circuitGarbling.garbleGRR3(0);
        circuitGarbling.garblePnP(0);
        circuitGarbling.initGarbleEQ();
    }

    /**
     * Init function for our garbled equivalence circuit, setting the keys and counting the gates.<br>
     * <b>NOTE</b>: this internally calls {@link #garbleGRR3EqXor(int[], int[], int)} and
     * {@link #garbleGRR3EqOr(int[], int[], int)}.
     */
    private void initGarbleEQ() {
        print("======EQ Circuit=====");
        int[][] keyL = new int[4][2];
        int[][] keyR = new int[4][2];
        int[][] keyO = new int[7][2];

        for (int i = 0; i < 4; i++) {
            keyL[i][0] = hashInsecure(2 * i);
            keyL[i][1] = keyL[i][0] ^ 32767;
            keyR[i][0] = hashInsecure(2 * i + 1);
            keyR[i][1] = keyR[i][0] ^ 32767;
            keyO[i] = garbleGRR3EqXor(keyL[i], keyR[i], i);
        }
        keyO[4] = garbleGRR3EqOr(keyO[0], keyO[1], 4);
        keyO[5] = garbleGRR3EqOr(keyO[2], keyO[3], 5);
        keyO[6] = garbleGRR3EqOr(keyO[4], keyO[5], 6);
        print("=====================");
    }

    /**
     * Function that garbles the XOR gate and returns the keys for the next gate.
     * Logs information about the keys and the garble table.
     *
     * @param keysL     left side keys, used for calculation of output keys and garbled table entries.
     * @param keysR     right side keys, used for calculation of output keys and garbled table entries.
     * @param gateIndex the index of the gate, used for calculation of output keys and garbled table entries.
     * @return calculated output keys of the XOR gate.
     */
    private int[] garbleGRR3EqXor(int keysL[], int keysR[], int gateIndex) {
        print("\nXOR gate with id= " + gateIndex);
        // Calculating the keys
        int[] keysOut = new int[2];
        keysOut[0] = 0;
        keysOut[0] = encryptInsecure(keysL[0], keysR[0], keysOut[0], gateIndex);
        keysOut[1] = hashInsecure(gateIndex + 8);
        // Print calculated keys
        print("\nKeys_L[0, 1] = " + Arrays.toString(keysL) + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysOut));
        // Encrypt the four values of the XOR gate
        int[] gtt = new int[4];
        gtt[0] = encryptInsecure(keysL[0], keysR[0], keysOut[0], gateIndex);
        gtt[1] = encryptInsecure(keysL[0], keysR[1], keysOut[1], gateIndex);
        gtt[2] = encryptInsecure(keysL[1], keysR[0], keysOut[1], gateIndex);
        gtt[3] = encryptInsecure(keysL[1], keysR[1], keysOut[0], gateIndex);
        // Print encrypted keys
        print("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gtt));
        return keysOut;
    }


    /**
     * Function that garbles the OR gate and returns the keys for the next gate.
     * Logs information about the keys and the garble table.
     *
     * @param keysL     left side keys, used for calculation of output keys and garbled table entries.
     * @param keysR     right side keys, used for calculation of output keys and garbled table entries.
     * @param gateIndex the index of the gate, used for calculation of output keys and garbled table entries.
     * @return calculated output keys of the OR gate.
     */
    private int[] garbleGRR3EqOr(int keysL[], int keysR[], int gateIndex) {
        print("\nOR gate with id= " + gateIndex);
        // Calculating the keys
        int[] keysOut = new int[2];
        keysOut[0] = 0;
        keysOut[0] = encryptInsecure(keysL[0], keysR[0], keysOut[0], gateIndex);
        keysOut[1] = hashInsecure(gateIndex + 8);
        // Print calculated keys
        print("\nKeys_L[0, 1] = " + Arrays.toString(keysL) + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysOut));
        // Encrypt the four values of the OR gate
        int[] gtt = new int[4];
        gtt[0] = encryptInsecure(keysL[0], keysR[0], keysOut[0], gateIndex);
        gtt[1] = encryptInsecure(keysL[0], keysR[1], keysOut[1], gateIndex);
        gtt[2] = encryptInsecure(keysL[1], keysR[0], keysOut[1], gateIndex);
        gtt[3] = encryptInsecure(keysL[1], keysR[1], keysOut[1], gateIndex);
        // Print encrypted keys
        print("\nEncKeys[0, 1, 2, 3] = " + Arrays.toString(gtt));
        return keysOut;
    }


    /**
     * Function that implements point and permute in combination with garbled row reduction.
     *
     * @param gateIndex index of the gate.
     * @see <a href="http://web.cs.ucdavis.edu/~rogaway/papers/bmr90">The Round Complexity of Secure Protocols</a>
     */
    @SuppressWarnings("SameParameterValue")
    private void garblePnP(int gateIndex) {
        print("=========PnP========");
        print("AND gate with id= " + gateIndex + "\n");
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = hashInsecure(2);
        keysO[1] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        // Printing calculated keys
        print("Keys_L[0, 1] = " + Arrays.toString(keysL) + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        gt[1] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        // Printing encrypted keys
        print("\ngt00= " + gt[0] + "\ngt01= " + gt[1] + "\ngt10= " + gt[2] + "\ngt11= " + gt[3]);
        print("=====================");
        resetKeyArrays();
    }

    /**
     * Function that implements Garbled Row Reduction.
     *
     * @param gateIndex index of the gate.
     * @see <a href="https://dl.acm.org/citation.cfm?id=337028">Privacy preserving auctions and mechanism design</a>
     */
    @SuppressWarnings("SameParameterValue")
    private void garbleGRR3(int gateIndex) {
        print("=========GRR3========");
        print("AND gate with id= " + gateIndex);
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        // keysO[0] is set to zero implicitly
        keysO[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        keysO[1] = hashInsecure(2);
        // Print calculated keys
        print("\nKeys_L[0, 1] = " + Arrays.toString(keysL) + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        // Print encrypted keys
        print("\ngt00= " + gt[0] + "\ngt01= " + gt[1] + "\ngt10= " + gt[2] + "\ngt11= " + gt[3]);
        print("=====================");
        resetKeyArrays();
    }

    /**
     * Function that garbles a single AND gate, given keyL⁰, keyL¹, keyR⁰, keyR¹ and gate index.
     * The function outputs two random keys keyO⁰, keyO¹ and a canonical sorted
     * (keyL⁰ keyR⁰, keyL⁰ keyR¹, keyL¹ keyR⁰, keyL¹ keyR¹) garbled table.
     *
     * @param gateIndex index of the gate.
     */
    @SuppressWarnings("SameParameterValue")
    private void garbleClassic(int gateIndex) {
        print("=======CLASSIC=======");
        print("AND gate with id= " + gateIndex);
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = hashInsecure(2);
        keysO[1] = hashInsecure(3);
        // Print calculated keys
        print("\nKeys_L[0, 1] = " + Arrays.toString(keysL) + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0], gateIndex);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0], gateIndex);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1], gateIndex);
        print("\ngt00= " + gt[0] + "\ngt01= " + gt[1] + "\ngt10= " + gt[2] + "\ngt11= " + gt[3]);
        print("=====================");
        resetKeyArrays();
    }

    /**
     * Resets the class fields to initial state.
     */
    private void resetKeyArrays() {
        for (int i = 0; i < 2; i++) {
            keysL[i] = 0;
            keysR[i] = 0;
            keysO[i] = 0;
            gt[i] = 0;
        }
        gt[2] = 0;
        gt[3] = 0;
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
