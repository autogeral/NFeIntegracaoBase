/*
 * Copyright (C) 2010  J. Computacao LTDA
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * If it is your itention to get support for a commercial version of this
 * application get in touch with J. Computacao LTDA at http://www.jcomputacao.com.br
 *
 * Este programa é software livre: voce pode redistribui-lo e/ou modifica-lo
 * sob os termos da Licenca Pulica Generica (GNU GPL) como publicado pela
 * Free Software Foundation, na versao 3 da licenca ou alguma versao superior.
 *
 * This programa e distribuido na esperanca que seja util,
 * mas SEM QUALQUER GARANTIA; sem sequer a garantia implicita
 * de COMERCIALIZACAO or APTIDAO PARA UMA FINALIDADE PARTICULAR.
 * Leia a GNU GPL para mais detalhes.
 *
 * Voce deveria receber uma copia da GNU GPL junto com este programa
 * se nao o recebeu leia em <http://www.gnu.org/licenses/>.
 *
 * Se for sua intencao obter suporte para uma versao comercial desta
 * aplicacao entre em contato com J. Computacao LTDA em http://www.jcomputacao.com.br
 *
 */

package br.com.jcomputacao.nfe.assinatura;

import br.com.jcomputacao.nfe.NFeUtil;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.util.Enumeration;


/**
 * Conteudo reterido e modificado de
 * http://www.guj.com.br/posts/list/52035.java#576483
 * @author Murilo
 */
public class Assinador {

    private static final String C14N_TRANSFORM_METHOD = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    private static final String PROVIDER_CLASS_NAME = "org.jcp.xml.dsig.internal.dom.XMLDSigRI";
    private static final String PROVIDER_NAME = "jsr105Provider";

    public static String assinar(String xml, String caminhoCertificado, String senha, AssinadorTipo tipo, String cnpj) throws Exception {
        String tag = "";
        if (AssinadorTipo.INFORMACAO.equals(tipo)) {
            tag = "infNFe";
        } else if (AssinadorTipo.CANCELAMENTO.equals(tipo)) {
            tag = "infEvento";
        } else if (AssinadorTipo.INUTILIZACAO.equals(tipo)) {
            tag = "infInut";
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        DocumentBuilder builder = factory.newDocumentBuilder();

        ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes(Charset.forName("UTF-8")));
        Document docs = builder.parse(bais);
        bais.close();
        
        NodeList elements = docs.getElementsByTagName(tag);
        if (elements.getLength() == 0) {
            throw new Exception("Nao conseguiu encontrar a TAG <" + tag + "> no documento\nXML : " + xml);
        }
        Element el = (Element) elements.item(0);
        el.setIdAttribute("Id", true);
        String id = el.getAttribute("Id");

        String providerName = System.getProperty(PROVIDER_NAME, PROVIDER_CLASS_NAME);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

        ArrayList transformList = new ArrayList();
        TransformParameterSpec tps = null;
        Transform envelopedTransform = fac.newTransform(Transform.ENVELOPED, tps);
        Transform c14NTransform = fac.newTransform(C14N_TRANSFORM_METHOD, tps);
        transformList.add(envelopedTransform);
        transformList.add(c14NTransform);

        Reference ref = fac.newReference("#" + id, fac.newDigestMethod(DigestMethod.SHA1, null), transformList, null, null);
        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null), fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null), Collections.singletonList(ref));

        KeyStore ks = null;
        if("A3".equals(NFeUtil.getCertificadoTipo(cnpj))) {
            String tokenCfg = System.getProperty("nfe.certificado.token.cfg", "C:\\DBF\\dist\\token.cfg");
            String className = "sun.security.pkcs11.SunPKCS11";
            Class<?> providerClass = Class.forName(className);
            if(providerClass==null) {
                throw new Exception("Nao encontrou a classe " + className + "\nPara conseguir assinar o documento!");
            }
            Constructor<?> constructor = providerClass.getConstructor(String.class);
            Provider p = (Provider) constructor.newInstance(tokenCfg);
            Security.addProvider(p);
            ks = KeyStore.getInstance("PKCS11");
            ks.load(null, senha.toCharArray());
        } else {
            ks = KeyStore.getInstance("PKCS12");
            InputStream is = new FileInputStream(caminhoCertificado);
            ks.load(is, senha.toCharArray());
            is.close();
        }
        //ks.load(new FileInputStream(caminhoCertificado), senha.toCharArray());
//        URL url = new URL(caminhoCertificado);
        
        Enumeration aliasesEnum = ks.aliases();
        String alias = "";
        while (aliasesEnum.hasMoreElements()) {
            alias = (String) aliasesEnum.nextElement();

            if (ks.isKeyEntry(alias)) {
                break;
            }
        }

        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(senha.toCharArray()));
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        // Create the KeyInfo containing the X509Data.
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        // x509Content.add(cert.getSubjectX500Principal().getName());

        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        // Instantiate the document to be signed.
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        bais = new ByteArrayInputStream(xml.getBytes(Charset.forName("UTF-8")));
        Document doc = dbf.newDocumentBuilder().parse(bais);
        bais.close();

        // Create a DOMSignContext and specify the RSA PrivateKey and
        // location of the resulting XMLSignature's parent element.
        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
        
        //INICIO 
        //tentando enviar NFe em qualquer Java, mas o código abaixo 
        //coloca a assinatura no lugar errado do XML, antes de fechar a tag </infNFe>
        //tem que ser depois
//        el = (Element) doc.getDocumentElement().getElementsByTagName(tag).item(0);
//        el.setIdAttribute("Id", true);
//        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), el);
        //FIM
        
        // Create the XMLSignature, but don't sign it yet.
        XMLSignature signature = fac.newXMLSignature(si, ki);

        // Marshal, generate, and sign the enveloped signature.
        signature.sign(dsc);

        // Output the resulting document.
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        //OutputStream os = new FileOutputStream(caminhoXmlNovo);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

        // Find Signature element.
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");

        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        // Create a DOMValidateContext and specify a KeySelector and document
        // context.
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(ks), nl.item(0));

        // Unmarshal the XMLSignature.
        XMLSignature signatures = fac.unmarshalXMLSignature(valContext);
        // Validate the XMLSignature.
        boolean coreValidity = signatures.validate(valContext);
        // Check core validation status.
        if (coreValidity == false) {
            System.err.println("Falha na Assinatura!");
        } else {
            System.out.println("Assinatura Correta!");
        }
        return os.toString("UTF-8");
    }

}
