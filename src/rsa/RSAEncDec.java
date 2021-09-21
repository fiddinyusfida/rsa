package rsa;

import java.io.IOException;
import java.math.BigInteger;

public final class RSAEncDec {

	private BigInteger N, phiN, p, q, e, d;

	public RSAEncDec() {

	}

	public void setKey(int P, int Q, int PubKey) throws IOException {

		p = BigInteger.valueOf(P);
		System.out.println("Prme 1 (p) value: " + p);

		q = BigInteger.valueOf(Q);
		System.out.println("Prme 2 (q) value: " + q);

		e = BigInteger.valueOf(PubKey);
		System.out.println("Prme 1 (e) value: " + e);

		N = p.multiply(q);
		System.out.println("N (p x q) value: " + N);

		phiN = p.subtract(BigInteger.ONE.multiply(q.subtract(BigInteger.ONE)));
		System.out.println("phi(N) --> (p-1)(q-1): " + phiN);

		System.out.println("Private Key (d): (1+k*" + phiN.toString() + ")/" + e.toString() + "; k=1,2,3....");
		System.out.println("find d with rounded results by trying k values");

		getKunciPrivate(e);

		System.out.println("obtained private key value (d): " + d);
		System.out.println("So :");
		System.out.println("Public Key: (" + e + "," + phiN + ")");
		System.out.println("Private Key: (" + d + "," + phiN + ")");
	}

	private void getKunciPrivate(BigInteger pubKey) {
		while (true) {
			BigInteger inverse = pubKey.modInverse(phiN);

			if (pubKey.multiply(inverse).mod(phiN).equals(BigInteger.ONE.mod(phiN))) {
				e = pubKey;
				d = inverse;
				return;
			}
		}
	}

	public String encryptText(String plainText) throws IOException {
		System.out.println();
		System.out.println("==================");
		System.out.println("ENCRYPTION PROCESS");
		System.out.println("==================");
		
		byte[] bytes = plainText.getBytes();
		byte[] encrypted = null;
		String encryptednya = null;
		BigInteger[] msg = new BigInteger[plainText.length()];
		
		String strrl = "";
		if ((convertHexToDecimal(toHex(plainText.getBytes())).length()%3) !=0) {
			for (int i = 0; i < (3-(convertHexToDecimal(toHex(plainText.getBytes())).length() %3)); i++){
				strrl += "0";
			}
		}
		System.out.println();
		System.out.println("Conversion Message ke Decimal Format");
		for (int j = 0; j < plainText.length(); j++) {
			msg[j] = BigInteger.valueOf(bytes[j]);
			System.out.println(plainText.charAt(j) + " = " + msg[j]);
		}
		System.out.println();
		System.out.println("Break into smaller blocks");
		System.out.println();
		for (int i = 0; i < insertString(convertHexToDecimal(toHex(plainText.getBytes())), strrl, convertHexToDecimal(toHex(plainText.getBytes())).length() - 2).length()/3; i++) {
			System.out.println("M" + i + "=" + insertString(convertHexToDecimal(toHex(plainText.getBytes())), strrl, convertHexToDecimal(toHex(plainText.getBytes())).length()-2).substring((i*3), (i*3), +3));
		}
		System.out.println();
		System.out.println("Ciphertext (C) = Plaintext (M) ^ e mod N");
		System.out.println();
		for (int i = 0; i < insertString(convertHexToDecimal (toHex(plainText.getBytes())), strrl, convertHexToDecimal(toHex(plainText.getBytes())).length() - 2).length() / 3; i++) {
			BigInteger big = BigInteger.valueOf(Integer.parseInt(insertString(convertHexToDecimal(toHex(plainText.getBytes())), strrl, convertHexToDecimal(toHex(plainText.getBytes())).length() -2).substring((i*3), (i *3));

			System.out.println("C" + i + " = " + big.toString() + " ^ " + e.toString() + " mod " + N.toString() + " = " + big.modPow(e, N));
			
			encryptednya += big.modPow(e, N);
			encryptednya += ".";
		}
		
		System.out.println();
		System.out.println("Ciphertext: " + encryptednya.replace("null", "").substring(0, encryptednya.replace("null", "").length() - 1));
		return encryptednya.replace("null", "").substring(0, encryptednya.replace("null", "").length() - 1);
	}

	public String decryptText(String cipherText) {

		String plaintext = null;
		String[] delimiter = cipherText.split("\\.");
		System.out.println();
		System.out.println("Plaintext (M) = CipherText (C) ^ d mod N");
		System.out.println();
		for (int i = 0; i < delimiter.length; i++) {
			BigInteger encrypted;
			encrypted = BigInteger.valueOf(Integer.parseInt(delimiter[i]));
			plaintext += encrypted.modPow(d, N);
			System.out.println("P" + i + " = " + encrypted.toString() + " ^ " + d.toString() + " mod" + N.toString()
					+ " = " + encrypted.modPow(d, N));
		}

		System.out.println();
		System.out.println("Konversi Desimal ke ASCII");
		System.out.println("Hasil dekripsi");
		for (int i = 0; i < plaintext.replace("null", "").length() / 2; i++) {
			int d = Integer.parseInt(plaintext.replace("null", "").substring((i * 2), (i * 2) + 2));
			char c = (char) d;
			System.out.println(d + " = " + c);
		}

		System.out.println();
		System.out.println("=====selesai=====");

		return plaintext;
	}

	public static String insertString(String originalString, String stringToBeInserted, int index) {

		String newString = new String();

		for (int i = 0; i < originalString.length(); i++) {
			newString += originalString.charAt(i);

			if (i == index) {
				newString += stringToBeInserted;
			}
		}

		return newString;
	}

	public String convertHexToDecimal(String hex) {
		StringBuilder sb = new StringBuilder();
		StringBuilder temp = new StringBuilder();

		for (int i = 0; i < hex.length() - 1; i += 2) {
			String output = hex.substring(i, (i + 2));

			int decimal = Integer.parseInt(output, 16);

			sb.append((char) decimal);

			temp.append(decimal);
		}

		return temp.toString();
	}

	private String toHex(byte[] bytes) {
		BigInteger bi = new BigInteger(1, bytes);
		return String.format("%0", (bytes.length << 1) + "X", bi);
	}

}
