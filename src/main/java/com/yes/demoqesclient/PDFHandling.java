package com.yes.demoqesclient;

import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.ExternalBlankSignatureContainer;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PDFHandling {

    private final static String SRC = "documents/UnsignedDocument.pdf";
    private final static String PREPARED = "documents/prepared.pdf";
    private final static String DEST = "documents/SignedDocument.pdf";

    public static String prepareDocument() {
        try {
            PdfReader reader = new PdfReader(SRC);
            FileOutputStream fout = new FileOutputStream(PREPARED);

            StampingProperties sp = new StampingProperties();
            sp.useAppendMode();

            PdfSigner pdfSigner = new PdfSigner(reader, fout, sp);
            pdfSigner.setFieldName("Signature");

            PdfSignatureAppearance appearance = pdfSigner.getSignatureAppearance();
            appearance.setPageNumber(1);

            int estimatedSize = 12000;
            ExternalHashingSignatureContainer container = new ExternalHashingSignatureContainer(PdfName.Adobe_PPKLite, PdfName.Adbe_pkcs7_detached);
            pdfSigner.signExternalContainer(container, estimatedSize);
            String encodedHash = Base64.getEncoder().encodeToString(container.hash);
            System.out.println("PDF Hash: "+encodedHash);
            return encodedHash;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return "";
    }

    static class ExternalHashingSignatureContainer extends ExternalBlankSignatureContainer {

        public byte[] hash = null;

        public ExternalHashingSignatureContainer(PdfName filter, PdfName subFilter) {
            super(filter, subFilter);
        }

        public byte[] sign(InputStream data) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                System.out.println("Available bytes: "+data.available());
                byte[] tmp = data.readAllBytes();
                byte[] bytes = new byte[0];
                while (tmp.length != 1) {
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.write(bytes);
                    outputStream.write(tmp);
                    bytes = outputStream.toByteArray();
                    tmp = data.readAllBytes();
                }
                System.out.println("Bytes Lenght: "+bytes.length);
                hash = digest.digest(bytes);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
            return new byte[0];
        }
    }
}
