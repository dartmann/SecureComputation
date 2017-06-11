import java.util.Arrays;
import java.util.logging.Logger;

public class CircuitGarbling {

    private static final Logger LOG = Logger.getLogger(CircuitGarbling.class.getSimpleName());

    public static void main(String[] args) {
        final CircuitGarbling circuitGarbling = new CircuitGarbling();
        circuitGarbling.garbleClassic();
    }

    private void garbleClassic() {
        LOG.info("=======CLASSIC=======");
        /*
        Fields to use for storing the keys
         */
        int[] keysL = new int[2];
        int[] keysR = new int[2];
        int[] keysO = new int[2];
        /*
        Field to store the encrypted values
         */
        int[] gt = new int[4];
        /*
        Calculating the keys
         */
        keysL[0] = hashInsecure(0);
        keysL[1] = keysL[0] ^ 32767;
        keysR[0] = hashInsecure(1);
        keysR[1] = keysR[0] ^ 32767;
        keysO[0] = hashInsecure(2);
        keysO[1] = hashInsecure(3);

        LOG.info("\nKeys_L[0, 1] = " + Arrays.toString(keysL)
                + "\nKeys_R[0, 1] = " + Arrays.toString(keysR)
                + "\nKeys_O[0, 1] = " + Arrays.toString(keysO));
        /*
        Encrypt the four values of the AND gate
         */
        gt[0] = encryptInsecure(keysL[0], keysR[0], keysO[0]);
        gt[1] = encryptInsecure(keysL[0], keysR[1], keysO[0]);
        gt[2] = encryptInsecure(keysL[1], keysR[0], keysO[0]);
        gt[3] = encryptInsecure(keysL[1], keysR[1], keysO[1]);
        LOG.info(Arrays.toString(gt));
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
    private int encryptInsecure(int keyL, int keyR, int keyO) {
        return hashInsecure(keyL ^ (keyR << 1)) ^ keyO;
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
