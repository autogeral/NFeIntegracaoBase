package br.com.jcomputacao.nfe;

import java.io.File;
import java.io.FileFilter;
import java.io.FileWriter;
import java.lang.reflect.Constructor;
import java.security.Provider;

/**
 *
 * @author murilo.lima
 */
public class CertificadoA3FileFilter implements FileFilter {

    private File f = null;
    private FileWriter fw = null;
    private String fileName;
    private String conteudo;
    private final String className = "sun.security.pkcs11.SunPKCS11";
    
    @Override
    public boolean accept(File f) {
        return f.getName().endsWith(".dll");
    }

    public boolean validaDll(String dll, String tipoCertificado) {
        boolean retorno = false;
        try {            
            Class<?> providerClass = Class.forName(className);
            if (providerClass == null) {
                throw new Exception("Nao encontrou a classe " + className + "\nPara conseguir assinar o documento!");
            }
            Constructor<?> constructor = providerClass.getConstructor(String.class);
            fileName = "C:/DBF/dist/token.cfg";
            conteudo = "name = " + tipoCertificado + "\tlibrary = " + "C:/Windows/System32/" + dll;
            f = new File(fileName);
            fw = new FileWriter(f);
            fw.write(conteudo);
            fw.flush();
            fw.close();
            String cfg = "C:\\DBF\\dist\\token.cfg";
            if(dll.equals("netlogon.dll")) {
                return false;
            }
            Provider p = (Provider) constructor.newInstance(cfg);
            if (p != null) {
                retorno = true;
            }
        } catch (Exception ex) {
            System.out.println(ex);            
            return false;
        }
        return retorno;
    }

}
