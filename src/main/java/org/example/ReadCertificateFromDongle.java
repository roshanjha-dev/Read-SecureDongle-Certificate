package org.example;

import sun.security.pkcs11.wrapper.CK_ATTRIBUTE;
import sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS;
import sun.security.pkcs11.wrapper.CK_SESSION_INFO;
import sun.security.pkcs11.wrapper.PKCS11;
import sun.security.pkcs11.wrapper.PKCS11Constants;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class ReadCertificateFromDongle {

    public static void main(String[] args) {
        String pkcs11Trustoken = "/home/roshan/MyData/Thesis/Trustoken/TrusToken-V-3.1/libtrustokenP11Lib.so";
        String pkcs11Epass = "/home/roshan/MyData/My_PKCS11_Code/libcastle_v2.so.1.0.0";
        String pin = "123456"; // Your PIN for the dongle

        try {
            // Initialize PKCS#11 library
            CK_C_INITIALIZE_ARGS initArgs = new CK_C_INITIALIZE_ARGS();
            PKCS11 pkcs11 = PKCS11.getInstance(pkcs11Trustoken, "C_GetFunctionList", initArgs, false);

            // Open a session
            long slotID = pkcs11.C_GetSlotList(true)[0];
            long sessionHandle = pkcs11.C_OpenSession(slotID, PKCS11Constants.CKF_SERIAL_SESSION | PKCS11Constants.CKF_RW_SESSION, null, null);
            System.out.println("Session opened with handle: " + sessionHandle);

            // Login to the token
            pkcs11.C_Login(sessionHandle, PKCS11Constants.CKU_USER, pin.toCharArray());

            // Search for the certificate object
            CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[2];
            template[0] = new CK_ATTRIBUTE(PKCS11Constants.CKA_CLASS, PKCS11Constants.CKO_CERTIFICATE);
            template[1] = new CK_ATTRIBUTE(PKCS11Constants.CKA_CERTIFICATE_TYPE, PKCS11Constants.CKC_X_509);
            pkcs11.C_FindObjectsInit(sessionHandle, template);
            long[] certificateHandles = pkcs11.C_FindObjects(sessionHandle, 1);
            pkcs11.C_FindObjectsFinal(sessionHandle);

            if (certificateHandles.length > 0) {
                long certificateHandle = certificateHandles[0];
                System.out.println("Certificate found with handle: " + certificateHandle);

                // Retrieve the certificate value
                CK_ATTRIBUTE[] attrs = new CK_ATTRIBUTE[1];
                attrs[0] = new CK_ATTRIBUTE(PKCS11Constants.CKA_VALUE);
                pkcs11.C_GetAttributeValue(sessionHandle, certificateHandle, attrs);

                byte[] certBytes = attrs[0].getByteArray();
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

                System.out.println("Certificate: " + certificate);
            } else {
                System.out.println("No certificate found.");
            }

            // Logout and close the session
            pkcs11.C_Logout(sessionHandle);
            pkcs11.C_CloseSession(sessionHandle);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

//public class ReadCertificateFromDongle {
//    public static void main(String[] args) {
//
////        String dllPath = "/home/roshan/My_PKCS11_Code/libtrustokenP11Lib.so";
//
//        try {
//            // Load the PKCS#11 configuration file
//            String pkcs11Config = "pkcs11.cfg";
//            SunPKCS11 provider = new SunPKCS11(pkcs11Config);
//            Security.addProvider(provider);
//
//            // Load the keystore from the PKCS#11 provider
//            KeyStore keyStore = KeyStore.getInstance("PKCS11", provider);
//            keyStore.load(null, "123456".toCharArray());
//
//            // List aliases in the keystore
//            Enumeration<String> aliases = keyStore.aliases();
//            while (aliases.hasMoreElements()) {
//                String alias = aliases.nextElement();
//                System.out.println("Alias: " + alias);
//
//                // Retrieve the certificate
//                Certificate certificate = keyStore.getCertificate(alias);
//                System.out.println("Certificate: " + certificate);
//            }
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//}
