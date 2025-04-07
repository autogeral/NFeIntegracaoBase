package br.com.jcomputacao.nfe.validacao;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;

/**
 * 25/02/2011 16:56:44
 * @author Murilo
 */
public class Validador {

    public void validar(String xml, ErrorHandler handler, URL schemaLocation) throws ParserConfigurationException, SAXException, IOException {
        //http://www.guj.com.br/java/70552-validar-xml-com-schema-usando-saxbuilder
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        System.out.println("DocumentBuilderFactory: " + factory.getClass().getName());

        factory.setNamespaceAware(true);
        factory.setValidating(true);
        factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaLanguage", "http://www.w3.org/2001/XMLSchema");
        factory.setAttribute("http://java.sun.com/xml/jaxp/properties/schemaSource", schemaLocation.toString());
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();
            builder.setErrorHandler(handler);
        } catch (ParserConfigurationException ex) {
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.SEVERE, "Erro ao montar o builder de XML", ex);
        }
        org.w3c.dom.Document document;
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(xml.getBytes());
            document = builder.parse(bais);
            bais.close();
            org.w3c.dom.Node rootNode = document.getFirstChild();
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.FINER, "Root node: {0}", rootNode.getNodeName());
        } catch (IOException ex) {
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.SEVERE, "Erro com o arquivo de origem", ex);
        } catch (SAXException ex) {
            Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.SEVERE, "Erro de XML", ex);
        }
    }

}
