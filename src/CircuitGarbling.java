import java.util.Arrays;

@SuppressWarnings({"SameParameterValue", "unused"})
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
     * Field to store the encrypted keys.
     */
    private final int[] gt = new int[4];

    public static void main(String[] args) {
        final CircuitGarbling circuitGarbling = new CircuitGarbling();
        circuitGarbling.garbleClassic(0);
        circuitGarbling.garbleGRR3(0);
        circuitGarbling.garblePnP(0);
        circuitGarbling.garbleEqualCircuit(0, 10, 10);
    }

    private void garbleEqualCircuit(int gateIndex, int a, int b) {
        print("=========PnP========");
        print("AND gate with id= " + gateIndex + "\n");
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[1] = hashInsecure(2);
        keysO[0] = encryptInsecure(keysL[1], keysR[1], keysO[0], gateIndex);
        // Printing calculated keys
        print("Keys_L[0, 1] = " + Arrays.toString(keysL) + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        // Encrypt the four values of the AND gate
        gt[0] = encryptInsecure(keysL[1], keysR[1], keysO[0], gateIndex);
        gt[1] = encryptInsecure(keysL[1], keysR[0], keysO[1], gateIndex);
        gt[2] = encryptInsecure(keysL[0], keysR[1], keysO[1], gateIndex);
        gt[3] = encryptInsecure(keysL[0], keysR[0], keysO[0], gateIndex);
        print("\ngt00= " + gt[0] + "\ngt01= " + gt[1] + "\ngt10= " + gt[2] + "\ngt11= " + gt[3]);
        //TODO
        print("=====================");
        resetKeyArrays();
    }

    /**
     * Function that implements point and permute in combination with garbled row reduction.
     *
     * @param gateIndex index of the gate.
     * @see <a href="http://web.cs.ucdavis.edu/~rogaway/papers/bmr90">The Round Complexity of Secure Protocols</a>
     */
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
     * Orders the keys {@link #keysL}, {@link #keysR} and appropriate {@link #keysO}
     * in an array by their LSB in canonical order.<br>
     * This fails if a key pair is not on the one side even (e.g. keyL⁰) and on the other side odd (e.g. keyL¹).
     *
     * @return ordered int array with dimension [4][3].
     */
    private int[][] orderCanonicalByLsb() {
        final int[][] orderedKeys = new int[4][3];
        // This approach only works, if keyL⁰ and keyL¹ OR keyR⁰ and keyR¹  differ in their LSB
        assert (keysL[0] % 2 == 0 && keysL[1] % 2 == 1) || (keysL[0] % 2 == 1 && keysL[1] % 2 == 0);
        assert (keysR[0] % 2 == 0 && keysR[1] % 2 == 1) || (keysR[0] % 2 == 1 && keysR[1] % 2 == 0);
        // First row of AND gate
        if (keysL[0] % 2 == 0 && keysR[0] % 2 == 0) {
            orderKeys(orderedKeys[0], keysL[0], keysR[0], keysO[0]);
        }
        if (keysL[0] % 2 == 0 && keysR[1] % 2 == 0) {
            orderKeys(orderedKeys[0], keysL[0], keysR[1], keysO[0]);
        }
        if (keysL[1] % 2 == 0 && keysR[0] % 2 == 0) {
            orderKeys(orderedKeys[0], keysL[1], keysR[0], keysO[0]);
        }
        if (keysL[1] % 2 == 0 && keysR[1] % 2 == 0) {
            orderKeys(orderedKeys[0], keysL[1], keysR[1], keysO[1]);
        }
        // Second row of AND gate
        if (keysL[0] % 2 == 0 && keysR[0] % 2 == 1) {
            orderKeys(orderedKeys[1], keysL[0], keysR[0], keysO[0]);
        }
        if (keysL[0] % 2 == 0 && keysR[1] % 2 == 1) {
            orderKeys(orderedKeys[1], keysL[0], keysR[1], keysO[0]);
        }
        if (keysL[1] % 2 == 0 && keysR[0] % 2 == 1) {
            orderKeys(orderedKeys[1], keysL[1], keysR[0], keysO[0]);
        }
        if (keysL[1] % 2 == 0 && keysR[1] % 2 == 1) {
            orderKeys(orderedKeys[1], keysL[1], keysR[1], keysO[1]);
        }
        // Third row of AND gate
        if (keysL[0] % 2 == 1 && keysR[0] % 2 == 0) {
            orderKeys(orderedKeys[2], keysL[0], keysR[0], keysO[0]);
        }
        if (keysL[0] % 2 == 1 && keysR[1] % 2 == 0) {
            orderKeys(orderedKeys[2], keysL[0], keysR[1], keysO[0]);
        }
        if (keysL[1] % 2 == 1 && keysR[0] % 2 == 0) {
            orderKeys(orderedKeys[2], keysL[1], keysR[0], keysO[0]);
        }
        if (keysL[1] % 2 == 1 && keysR[1] % 2 == 0) {
            orderKeys(orderedKeys[2], keysL[1], keysR[1], keysO[1]);
        }
        // Fourth row of AND gate
        if (keysL[0] % 2 == 1 && keysR[0] % 2 == 1) {
            orderKeys(orderedKeys[3], keysL[0], keysR[0], keysO[0]);
        }
        if (keysL[0] % 2 == 1 && keysR[1] % 2 == 1) {
            orderKeys(orderedKeys[3], keysL[0], keysR[1], keysO[0]);
        }
        if (keysL[1] % 2 == 1 && keysR[0] % 2 == 1) {
            orderKeys(orderedKeys[3], keysL[1], keysR[0], keysO[0]);
        }
        if (keysL[1] % 2 == 1 && keysR[1] % 2 == 1) {
            orderKeys(orderedKeys[3], keysL[1], keysR[1], keysO[1]);
        }
        return orderedKeys;
    }

    /**
     * Sets the three given keys on their appropriate index in a given inner index of the canonical ordered array of
     * {@link #orderCanonicalByLsb()}.
     *
     * @param innerOrderedKeys given inner index.
     * @param keyL             key left.
     * @param keyR             key right.
     * @param keyO             key output.
     */
    private void orderKeys(int[] innerOrderedKeys, int keyL, int keyR, int keyO) {
        innerOrderedKeys[0] = keyL;
        innerOrderedKeys[1] = keyR;
        innerOrderedKeys[2] = keyO;
        //print("HIT with keyL= " + keyL + ", keyR= " + keyR + ", keyO= " + keyO);
    }

    /**
     * Function that implements Garbled Row Reduction.
     *
     * @param gateIndex index of the gate.
     * @see <a href="https://dl.acm.org/citation.cfm?id=337028">Privacy preserving auctions and mechanism design</a>
     */
    private void garbleGRR3(int gateIndex) {
        print("=========GRR3========");
        print("AND gate with id= " + gateIndex);
        // Calculating the keys
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
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
