/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package br.inf.portalfiscal.nfe.xml.pl006q.assinatura;


import br.com.jcomputacao.nfe.assinatura.Assinador;
import br.com.jcomputacao.nfe.assinatura.AssinadorTipo;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.ObjectFactory;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TEnderEmi;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TNFe;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TNFe.InfNFe;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TNFe.InfNFe.Emit;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TNFe.InfNFe.InfAdic;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TNfeProc;
import br.inf.portalfiscal.nfe.xml.pl008f.nfes.TUfEmi;
import java.io.ByteArrayOutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Murilo.Lima
 */
public class AssinaturaTest {
    
    public AssinaturaTest() {
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
     public void hello() {
         ObjectFactory of = new ObjectFactory();
         TNFe tnfe = of.createTNFe();
         TNfeProc tnfeProc = of.createTNfeProc();
         InfNFe inf = new InfNFe();
         
         inf.setId("35130205437537000137550010001184261000000941");
         Emit emit = new Emit();
         emit.setXNome("AUTO GERAL DE ITU LTDA");
         emit.setXFant("AUTO GERAL LTDA");
         emit.setIM("12677");
         emit.setIE("387034155115");
         emit.setCNPJ("05437537000137");
         
         TEnderEmi endEmit = new TEnderEmi();
         endEmit.setCEP("13301909");
         endEmit.setCMun("ITU");
         endEmit.setFone("01140137777");
         endEmit.setUF(TUfEmi.SP);
         
         emit.setEnderEmit(endEmit);
         
         inf.setEmit(emit);
         
         InfAdic infAdic = new InfAdic();
         infAdic.setInfAdFisco("NFE de TESTE - SEM VALIDADE FISCAL");
         infAdic.setInfCpl("NFE emitida em homologacao");
         
         inf.setInfAdic(infAdic);
         tnfe.setInfNFe(inf);
         tnfeProc.setNFe(tnfe);
        try {
            JAXBContext context = JAXBContext.newInstance("br.inf.portalfiscal.nfe.xml.pl006q.nfes");
            Marshaller marshaller = context.createMarshaller();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
            marshaller.marshal(tnfeProc, baos);
            
            String xml = baos.toString().trim().replaceFirst("^([\\W]+)<","<");
            System.out.println("XML sem assinatura : "+xml);
            
            
            String certificadoCaminho = "C:/Users/Murilo.Lima/Desktop/A120140311F.pfx";
            String senha = "498408800406";
            AssinadorTipo assinadorTipo = AssinadorTipo.INFORMACAO;
            String expResult = "";
            try {
                String result = Assinador.assinar(xml, certificadoCaminho, senha, assinadorTipo, "05437537000137");
                System.out.println(result);
                System.out.flush();
                assertEquals(expResult, result);
                fail("The test case is a prototype.");
            } catch (Exception ex) {
                Logger.getLogger(AssinaturaTest.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        } catch (JAXBException ex) {
            ex.printStackTrace();
        }
     }
}
