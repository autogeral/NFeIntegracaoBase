/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.inf.portalfiscal.nfe.xml.pl006q.validacao;

import br.com.jcomputacao.nfe.validacao.Validador;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.ErrorHandler;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 *
 * @author Murilo.Lima
 */
public class ValidadorTest {
    
    public ValidadorTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }
    
    @Test
    public void hello() throws MalformedURLException, ParserConfigurationException, SAXException, IOException {
        String xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                + "<nfeProc>"
                + "<infNFe Id=\"35130205437537000137550010001184261000000941\">"
                + "<emit>"
                + "<CNPJ>99.999.999/0001-99</CNPJ><xNome>Evil Corporation</xNome>"
                + "<xFant>J. Computacao LTDA ME</xFant><enderEmit>"
                + "<xMun>ITU</xMun><UF>SP</UF><CEP>13300-090</CEP>"
                + "<fone>01124299930</fone></enderEmit><IE/><CNAE>1234567</CNAE>"
                + "</emit>"
                + "<infAdic><infAdFisco>NFE de TESTE - SEM VALIDADE FISCAL</infAdFisco>"
                + "<infCpl>NFE emitida em homologacao</infCpl></infAdic>"
                + "</infNFe>"
                + "</nfeProc>";        
        ErrorHandler handler = new ErrorHandler() {

            @Override
            public void warning(SAXParseException exception) throws SAXException {
                Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.SEVERE, "WARNING", exception);
            }

            @Override
            public void error(SAXParseException exception) throws SAXException {
                Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.SEVERE, "ERROR", exception);
            }

            @Override
            public void fatalError(SAXParseException exception) throws SAXException {
                Logger.getLogger(Logger.GLOBAL_LOGGER_NAME).log(Level.SEVERE, "FATAL", exception);
            }
        };
        xml = xml.replaceAll("xmlns:ns2=\".+#\"\\s", "").replaceAll("ns2:", "");
        xml = xml.trim().replaceFirst("^([\\W]+)<","<");
        URL schemaLocation = new URL("file:///Users/Murilo.Lima/Documents/DBFAssinado2/NFeXML2PL006q/src/br/com/jcomputacao/nfe/xml/pl006q/consSitNFe_v2.01.xsd");
        Validador instance = new Validador();
        instance.validar(xml, handler, schemaLocation);
        fail("The test case is a prototype.");
    }
}
