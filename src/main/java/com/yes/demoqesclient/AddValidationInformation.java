/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yes.demoqesclient;

import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;

/**
 * An example for adding Validation Information to a signed PDF, inspired by ETSI TS 102 778-4
 * V1.1.2 (2009-12), Part 4: PAdES Long Term - PAdES-LTV Profile. This procedure appends the
 * Validation Information of the last signature (more precise its signer(s)) to a copy of the
 * document. The signature and the signed data will not be touched and stay valid.
 * <p>
 * See also <a href="http://eprints.hsr.ch/id/eprint/616">Bachelor thesis (in German) about LTV</a>
 *
 * @author Alexis Suter
 */
public class AddValidationInformation {
    /**
     * Gets or creates a dictionary entry. If existing checks for the type and sets need to be
     * updated.
     *
     * @param clazz the class of the dictionary entry, must implement COSUpdateInfo
     * @param parent where to find the element
     * @param name of the element
     * @return a Element of given class, new or existing
     * @throws IOException when the type of the element is wrong
     */
    protected static <T extends COSBase & COSUpdateInfo> T getOrCreateDictionaryEntry(Class<T> clazz,
                                                                                    COSDictionary parent, String name) throws IOException
    {
        T result;
        COSBase element = parent.getDictionaryObject(name);
        if (element != null && clazz.isInstance(element))
        {
            result = clazz.cast(element);
            result.setNeedToBeUpdated(true);
        }
        else if (element != null)
        {
            throw new IOException("Element " + name + " from dictionary is not of type "
                    + clazz.getCanonicalName());
        }
        else
        {
            try
            {
                result = clazz.getDeclaredConstructor().newInstance();
            }
            catch (InstantiationException ex)
            {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), ex);
            }
            catch (IllegalAccessException ex)
            {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), ex);
            }
            catch (NoSuchMethodException ex)
            {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), ex);
            }
            catch (SecurityException ex)
            {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), ex);
            }
            catch (IllegalArgumentException ex)
            {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), ex);
            }
            catch (InvocationTargetException ex)
            {
                throw new IOException("Failed to create new instance of " + clazz.getCanonicalName(), ex);
            }
            result.setDirect(false);
            parent.setItem(COSName.getPDFName(name), result);
        }
        return result;
    }

    /**
     * Adds Extensions to the document catalog. So that the use of DSS is identified. Described in
     * PAdES Part 4, Chapter 4.4.
     *
     * @param catalog to add Extensions into
     */
    protected static void addExtensions(PDDocumentCatalog catalog)
    {
        COSDictionary dssExtensions = new COSDictionary();
        dssExtensions.setDirect(true);
        catalog.getCOSObject().setItem("Extensions", dssExtensions);

        dssExtensions.setName(COSName.TYPE, "Extensions");

        COSDictionary adbeExtension = new COSDictionary();
        adbeExtension.setDirect(true);
        dssExtensions.setItem("ESIC", adbeExtension);

        adbeExtension.setName("BaseVersion", "1.7");
        adbeExtension.setName(COSName.TYPE, "DeveloperExtensions");
        adbeExtension.setInt("ExtensionLevel", 5);

        catalog.setVersion("1.7");
    }

    /**
     * Creates a Flate encoded <code>COSStream</code> object with the given data.
     *
     * @param data to write into the COSStream
     * @return COSStream a COSStream object that can be added to the document
     * @throws IOException
     */
    protected static COSStream writeDataToStream(byte[] data, PDDocument document) throws IOException
    {
        COSStream stream = document.getDocument().createCOSStream();
        OutputStream os = null;
        try
        {
            os = stream.createOutputStream(COSName.FLATE_DECODE);
            os.write(data);
        }
        finally
        {
            IOUtils.closeQuietly(os);
        }
        return stream;
    }

}
