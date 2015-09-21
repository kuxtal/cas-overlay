package mx.japs.portal.configuracion.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.syncope.common.SyncopeConstants;
import org.apache.syncope.common.types.CipherAlgorithm;
import org.jasypt.commons.CommonUtils;
import org.jasypt.digest.StandardStringDigester;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.codec.Base64;

public class Encryptor {
	protected static final Logger logger = LoggerFactory.getLogger(Encryptor.class);

    private static final String DEFAULT_SECRET_KEY = "1abcdefghilmnopqrstuvz2!";

    /**
     * Default value for salted {@link StandardStringDigester#setIterations(int)}.
     */
    private static final int DEFAULT_SALT_ITERATIONS = 1;

    /**
     * Default value for {@link StandardStringDigester#setSaltSizeBytes(int)}.
     */
    private static final int DEFAULT_SALT_SIZE_BYTES = 8;

    /**
     * Default value for {@link StandardStringDigester#setInvertPositionOfPlainSaltInEncryptionResults(boolean)}.
     */
    private static final boolean DEFAULT_IPOPSIER = true;

    /**
     * Default value for salted {@link StandardStringDigester#setInvertPositionOfSaltInMessageBeforeDigesting(boolean)}.
     */
    private static final boolean DEFAULT_IPOSIMBD = true;

    /**
     * Default value for salted {@link StandardStringDigester#setUseLenientSaltSizeCheck(boolean)}.
     */
    private static final boolean DEFAULT_ULSSC = true;

    private static String secretKey;

    private static Integer saltIterations;

    private static Integer saltSizeBytes;

    private static Boolean ipopsier;

    private static Boolean iposimbd;

    private static Boolean ulssc;

    /**
     * Get predefined password cipher algorithm from SyncopeConf.
     *
     * @return cipher algorithm.
     */
    public static CipherAlgorithm getPredefinedCipherAlgoritm() {
        return CipherAlgorithm.SHA256;
    }
    
    public Encryptor(){
    	InputStream propStream = null;
        try {
            propStream = Encryptor.class.getResourceAsStream("/security.properties");
            Properties props = new Properties();
            
            logger.debug("Cargando propiedades");
            props.load(propStream);
            

            secretKey = props.getProperty("secretKey");
            saltIterations = Integer.valueOf(props.getProperty("digester.saltIterations"));
            saltSizeBytes = Integer.valueOf(props.getProperty("digester.saltSizeBytes"));
            ipopsier = Boolean.valueOf(props.getProperty("digester.invertPositionOfPlainSaltInEncryptionResults"));
            iposimbd = Boolean.valueOf(props.getProperty("digester.invertPositionOfSaltInMessageBeforeDigesting"));
            ulssc = Boolean.valueOf(props.getProperty("digester.useLenientSaltSizeCheck"));
            logger.debug("Fin de carga de propiedades");
        } catch (Exception e) {
        	logger.error("Could not read security parameters", e);
        } finally {
        	try {
				propStream.close();
			} catch (IOException e) {
				logger.error("No se pudo cerrar el archivo de parametros", e);
			}
        }

        if (secretKey == null) {
            secretKey = DEFAULT_SECRET_KEY;
            logger.debug("secretKey not found, reverting to default");
        }
        if (saltIterations == null) {
            saltIterations = DEFAULT_SALT_ITERATIONS;
            logger.debug("digester.saltIterations not found, reverting to default");
        }
        if (saltSizeBytes == null) {
            saltSizeBytes = DEFAULT_SALT_SIZE_BYTES;
            logger.debug("digester.saltSizeBytes not found, reverting to default");
        }
        if (ipopsier == null) {
            ipopsier = DEFAULT_IPOPSIER;
            logger.debug("digester.invertPositionOfPlainSaltInEncryptionResults not found, reverting to default");
        }
        if (iposimbd == null) {
            iposimbd = DEFAULT_IPOSIMBD;
            logger.debug("digester.invertPositionOfSaltInMessageBeforeDigesting not found, reverting to default");
        }
        if (ulssc == null) {
            ulssc = DEFAULT_ULSSC;
            logger.debug("digester.useLenientSaltSizeCheck not found, reverting to default");
        }
        
        String actualKey = secretKey;
        if (actualKey.length() < 16) {
            StringBuilder actualKeyPadding = new StringBuilder(actualKey);
            for (int i = 0; i < 16 - actualKey.length(); i++) {
                actualKeyPadding.append('0');
            }
            actualKey = actualKeyPadding.toString();
            logger.debug("actualKey too short, adding some random characters");
        }

        try {
            keySpec = new SecretKeySpec(ArrayUtils.subarray(
                    actualKey.getBytes(SyncopeConstants.DEFAULT_ENCODING), 0, 16),
                    CipherAlgorithm.AES.getAlgorithm());
        } catch (Exception e) {
        	logger.error("Error during key specification", e);
        }
    }

    private SecretKeySpec keySpec;

    public String encode(final String value, final CipherAlgorithm cipherAlgorithm)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
    	
    	logger.debug("encode {}", value);

        String encodedValue = null;

        if (value != null) {
            if (cipherAlgorithm == null || cipherAlgorithm == CipherAlgorithm.AES) {
                final byte[] cleartext = value.getBytes(SyncopeConstants.DEFAULT_ENCODING);

                final Cipher cipher = Cipher.getInstance(CipherAlgorithm.AES.getAlgorithm());
                cipher.init(Cipher.ENCRYPT_MODE, keySpec);

                encodedValue = new String(Base64.encode(cipher.doFinal(cleartext)));
            } else if (cipherAlgorithm == CipherAlgorithm.BCRYPT) {
                encodedValue = BCrypt.hashpw(value, BCrypt.gensalt());
            } else {
                encodedValue = getDigester(cipherAlgorithm).digest(value);
            }
        }

        return encodedValue;
    }

    public boolean verify(final String value, final CipherAlgorithm cipherAlgorithm, final String encodedValue) {
        boolean res = false;

        try {
            if (value != null) {
                if (cipherAlgorithm == null || cipherAlgorithm == CipherAlgorithm.AES) {
                    res = encode(value, cipherAlgorithm).equals(encodedValue);
                } else if (cipherAlgorithm == CipherAlgorithm.BCRYPT) {
                    res = BCrypt.checkpw(value, encodedValue);
                } else {
                    res = getDigester(cipherAlgorithm).matches(value, encodedValue);
                }
            }
        } catch (Exception e) {
        	logger.error("Could not verify encoded value", e);
        }

        return res;
    }

    public String decode(final String encodedValue, final CipherAlgorithm cipherAlgorithm)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
    	logger.debug("decode {}", encodedValue);
    	
        String value = null;

        if (encodedValue != null && cipherAlgorithm == CipherAlgorithm.AES) {
            final byte[] encoded = encodedValue.getBytes(SyncopeConstants.DEFAULT_ENCODING);

            final Cipher cipher = Cipher.getInstance(CipherAlgorithm.AES.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, keySpec);

            value = new String(cipher.doFinal(Base64.decode(encoded)), SyncopeConstants.DEFAULT_ENCODING);
        }

        return value;
    }

    private StandardStringDigester getDigester(final CipherAlgorithm cipherAlgorithm) {
        StandardStringDigester digester = new StandardStringDigester();

        if (cipherAlgorithm.getAlgorithm().startsWith("S-")) {
            // Salted ...
            digester.setAlgorithm(cipherAlgorithm.getAlgorithm().replaceFirst("S\\-", ""));
            digester.setIterations(saltIterations);
            digester.setSaltSizeBytes(saltSizeBytes);
            digester.setInvertPositionOfPlainSaltInEncryptionResults(ipopsier);
            digester.setInvertPositionOfSaltInMessageBeforeDigesting(iposimbd);
            digester.setUseLenientSaltSizeCheck(ulssc);
        } else {
            // Not salted ...
            digester.setAlgorithm(cipherAlgorithm.getAlgorithm());
            digester.setIterations(1);
            digester.setSaltSizeBytes(0);
        }

        digester.setStringOutputType(CommonUtils.STRING_OUTPUT_TYPE_HEXADECIMAL);
        return digester;
    }
}